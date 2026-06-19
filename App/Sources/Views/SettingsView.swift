import SVPNModels
import SwiftUI

/// The single-profile editor. ShadowVPN has one connection, so Settings *is*
/// the profile form: server/port, the PSK, cipher and split-routing mode, plus
/// the ChinaDNS upstreams (shown only in that mode). Edits live in a string-
/// backed ``EditableProfile`` and are committed back into ``AppModel`` (which
/// persists to the App Group and pushes into the NE configuration) only on save.
struct SettingsView: View {
    @Environment(AppModel.self) private var appModel
    @Environment(VpnManager.self) private var vpnManager

    /// Working copy of the profile, seeded from the model. Re-seeded from the
    /// model whenever the saved profile changes (e.g. another path edits it).
    @State private var form: EditableProfile
    /// App-wide prefs not part of a connection profile (on-demand, log level).
    @State private var preferences: Preferences = .load(from: AppGroup.defaults)
    /// Brief confirmation after a successful save.
    @State private var savedConfirmation = false

    init() {
        // A placeholder `EditableProfile`; replaced from the environment model
        // in `.onAppear` (the environment isn't available in `init`).
        _form = State(initialValue: EditableProfile(Profile()))
    }

    var body: some View {
        Form {
            serverSection
            securitySection
            routingSection
            if form.showsDNSFields {
                dnsSection
            }
            generalSection
            aboutSection
        }
        .scrollContentBackground(.hidden)
        .background(AppTheme.screenBackground)
        .navigationTitle("settings.nav.title")
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("settings.save", action: save)
                    .disabled(!canSave)
                    .accessibilityIdentifier("settings.save")
            }
        }
        .onAppear {
            // Adopt the live profile the first time the view appears (and after
            // a return that may have changed it elsewhere) unless the user has
            // unsaved edits in progress.
            if !form.differs(from: appModel.profile) {
                form = EditableProfile(appModel.profile)
            }
        }
        .overlay(alignment: .bottom) {
            if savedConfirmation {
                savedToast
            }
        }
    }

    // MARK: - Server

    private var serverSection: some View {
        Section("settings.section.server") {
            LabeledField("settings.field.name", text: $form.name, identifier: "settings.field.name")
            LabeledField(
                "settings.field.server",
                text: $form.server,
                placeholder: "vpn.example.com",
                identifier: "settings.field.server",
            )
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .keyboardType(.URL)
            LabeledField(
                "settings.field.port",
                text: $form.portText,
                placeholder: "8388",
                identifier: "settings.field.port",
            )
            .keyboardType(.numberPad)
        }
    }

    // MARK: - Security

    private var securitySection: some View {
        Section("settings.section.security") {
            HStack {
                Text("settings.field.password")
                Spacer()
                SecureField("settings.field.password.placeholder", text: $form.password)
                    .multilineTextAlignment(.trailing)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("settings.field.password")
            }
            Picker("settings.field.cipher", selection: $form.cipher) {
                ForEach(Cipher.allCases) { cipher in
                    Text(cipher.displayName).tag(cipher)
                }
            }
            .accessibilityIdentifier("settings.field.cipher")
        }
    }

    // MARK: - Routing

    private var routingSection: some View {
        Section {
            Picker("settings.field.mode", selection: $form.mode) {
                ForEach(TunnelMode.allCases) { mode in
                    Text(mode.displayName).tag(mode)
                }
            }
            .accessibilityIdentifier("settings.field.mode")
        } header: {
            Text("settings.section.routing")
        } footer: {
            Text(modeFooter)
        }
    }

    private var modeFooter: LocalizedStringKey {
        switch form.mode {
        case .full: "settings.mode.full.footer"
        case .chnroute: "settings.mode.chnroute.footer"
        case .chinadns: "settings.mode.chinadns.footer"
        }
    }

    // MARK: - ChinaDNS upstreams (conditional)

    private var dnsSection: some View {
        Section {
            LabeledField(
                "settings.field.dnsLocal",
                text: $form.dnsLocal,
                placeholder: Profile.defaultDNSLocal,
                identifier: "settings.field.dnsLocal",
            )
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .keyboardType(.numbersAndPunctuation)
            LabeledField(
                "settings.field.dnsRemote",
                text: $form.dnsRemote,
                placeholder: Profile.defaultDNSRemote,
                identifier: "settings.field.dnsRemote",
            )
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .keyboardType(.numbersAndPunctuation)
        } header: {
            Text("settings.section.dns")
        } footer: {
            Text("settings.section.dns.footer")
        }
    }

    // MARK: - General prefs + advanced

    private var generalSection: some View {
        Section("settings.section.general") {
            Toggle("settings.toggle.onDemand", isOn: onDemandBinding)
                .accessibilityIdentifier("settings.toggle.onDemand")
            LabeledField(
                "settings.field.mtu",
                text: $form.mtuText,
                placeholder: String(Profile.defaultMTU),
                identifier: "settings.field.mtu",
            )
            .keyboardType(.numberPad)
        }
    }

    private var onDemandBinding: Binding<Bool> {
        Binding(
            get: { preferences.onDemand },
            set: { newValue in
                preferences.onDemand = newValue
                preferences.save(to: AppGroup.defaults)
            },
        )
    }

    // MARK: - About

    private var aboutSection: some View {
        Section("settings.section.about") {
            LabeledContent("settings.about.version", value: appVersion)
                .accessibilityIdentifier("settings.about.version")
            if vpnManager.traffic.footprintMB > 0 {
                LabeledContent("settings.about.memory", value: "\(vpnManager.traffic.footprintMB) MB")
                    .accessibilityIdentifier("settings.about.memory")
                    .accessibilityAddTraits(.updatesFrequently)
            }
        }
    }

    private var appVersion: String {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "1.0.0"
    }

    // MARK: - Save

    /// Save is enabled only when the form is complete and actually differs from
    /// the persisted profile — no point re-pushing an identical config into the
    /// NE (which would otherwise trigger a needless reconnect on next connect).
    private var canSave: Bool {
        form.isComplete && form.differs(from: appModel.profile)
    }

    private func save() {
        appModel.updateProfile(form.makeProfile())
        // Re-seed from the now-canonical profile so `differs` reads false and
        // the save button disables until the next edit.
        form = EditableProfile(appModel.profile)
        withAnimation { savedConfirmation = true }
        Task {
            try? await Task.sleep(for: .seconds(1.6))
            withAnimation { savedConfirmation = false }
        }
    }

    private var savedToast: some View {
        Label("settings.saved", systemImage: "checkmark.circle.fill")
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .background(AppTheme.connected, in: .capsule)
            .padding(.bottom, 24)
            .transition(.move(edge: .bottom).combined(with: .opacity))
            .accessibilityIdentifier("settings.savedToast")
    }
}

/// A trailing-aligned labeled `TextField` row, matching the Form aesthetic used
/// throughout Settings. Pulled out so each call site stays a single line.
private struct LabeledField: View {
    let title: LocalizedStringKey
    @Binding var text: String
    var placeholder: String = ""
    let identifier: String

    init(
        _ title: LocalizedStringKey,
        text: Binding<String>,
        placeholder: String = "",
        identifier: String,
    ) {
        self.title = title
        _text = text
        self.placeholder = placeholder
        self.identifier = identifier
    }

    var body: some View {
        HStack {
            Text(title)
            Spacer()
            TextField(placeholder, text: $text)
                .multilineTextAlignment(.trailing)
                .accessibilityIdentifier(identifier)
        }
    }
}
