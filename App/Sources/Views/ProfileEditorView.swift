import SVPNModels
import SwiftUI

/// Editor for a single connection ``Profile``, presented as a sheet from the
/// Profiles tab (both for creating a new profile and editing an existing one).
/// Edits live in a string-backed ``EditableProfile`` and are committed back into
/// ``AppModel`` — which persists the list and, if this is the active profile,
/// pushes it into the NE configuration — only on save.
struct ProfileEditorView: View {
    @Environment(AppModel.self) private var appModel
    @Environment(\.dismiss) private var dismiss

    /// Identity of the profile being edited. The working copy is seeded from the
    /// matching entry in the model (or a fresh default if it has since vanished).
    let profileID: UUID

    @State private var form: EditableProfile

    init(profileID: UUID, profile: Profile) {
        self.profileID = profileID
        _form = State(initialValue: EditableProfile(profile))
    }

    var body: some View {
        Form {
            serverSection
            securitySection
            routingSection
            if form.mode != .full {
                bypassCountrySection
            }
            if form.showsDNSFields {
                dnsSection
            }
            obfuscationSection
            advancedSection
        }
        .scrollContentBackground(.hidden)
        .background(AppTheme.screenBackground)
        .navigationTitle("editor.nav.title")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("editor.cancel") { dismiss() }
                    .accessibilityIdentifier("editor.cancel")
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("editor.save", action: save)
                    .disabled(!form.isComplete)
                    .accessibilityIdentifier("editor.save")
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
        case .chinadns: "settings.mode.chinadns.footer"
        }
    }

    // MARK: - Bypass country (split modes)

    private var bypassCountrySection: some View {
        Section {
            Picker("settings.field.country", selection: $form.bypassCountry) {
                if !form.bypassCountry.isEmpty, Country.named(form.bypassCountry) == nil {
                    Text(form.bypassCountry).tag(form.bypassCountry)
                }
                ForEach(Country.catalog) { country in
                    Text(country.pickerLabel).tag(country.code)
                }
            }
            .accessibilityIdentifier("settings.field.country")
        } header: {
            Text("settings.section.country")
        } footer: {
            Text("settings.section.country.footer")
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

    // MARK: - Obfuscation

    private var obfuscationSection: some View {
        Section {
            Picker("editor.field.obfuscation", selection: $form.obfuscation) {
                ForEach(Obfuscation.allCases) { obfs in
                    Text(obfs.displayName).tag(obfs)
                }
            }
            .accessibilityIdentifier("editor.field.obfuscation")
        } header: {
            Text("editor.section.obfuscation")
        } footer: {
            Text("editor.section.obfuscation.footer")
        }
    }

    // MARK: - Advanced

    private var advancedSection: some View {
        Section {
            LabeledField(
                "settings.field.mtu",
                text: $form.mtuText,
                placeholder: String(Profile.defaultMTU),
                identifier: "settings.field.mtu",
            )
            .keyboardType(.numberPad)
            Toggle("settings.field.autoIP", isOn: $form.autoIP)
                .accessibilityIdentifier("settings.field.autoIP")
            // The static peer IP is only used when the server isn't assigning one.
            if !form.autoIP {
                LabeledField(
                    "settings.field.peerIP",
                    text: $form.peerIP,
                    placeholder: Profile.defaultPeerIP,
                    identifier: "settings.field.peerIP",
                )
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.numbersAndPunctuation)
            }
        } header: {
            Text("settings.section.advanced")
        } footer: {
            Text(form.autoIP ? "settings.field.autoIP.footer" : "settings.field.peerIP.footer")
        }
    }

    // MARK: - Save

    private func save() {
        appModel.updateProfile(form.makeProfile())
        dismiss()
    }
}

/// A trailing-aligned labeled `TextField` row, matching the Form aesthetic used
/// throughout the editor. Internal so other views in the target can reuse it.
struct LabeledField: View {
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
