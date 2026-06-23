import AudioToolbox
import AVFoundation
import SwiftUI
import UIKit

/// A full-screen QR-code scanner presented as a sheet. Wraps an `AVFoundation`
/// capture session (via ``QRCameraView``) behind a SwiftUI chrome: a framing
/// reticle, a hint, and a Cancel button. Reports the first decoded string back
/// through ``onScan`` and dismisses; surfaces a friendly message when the camera
/// is unavailable or permission was denied.
///
/// The parser (``ProfileURI``) and the import flow live in the caller — this view
/// is only responsible for turning the camera into a single scanned string.
struct QRScannerView: View {
    /// Called once with the decoded payload of the first QR code seen.
    let onScan: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var status: CameraStatus = .checking

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()

                switch status {
                case .checking:
                    ProgressView()
                        .tint(.white)
                case .authorized:
                    scanner
                case .denied:
                    deniedNotice
                case .unavailable:
                    unavailableNotice
                }
            }
            .navigationTitle("scan.nav.title")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("scan.cancel") { dismiss() }
                        .tint(.white)
                        .accessibilityIdentifier("scan.cancel")
                }
            }
            .toolbarBackground(.black, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbarColorScheme(.dark, for: .navigationBar)
        }
        .task { await requestAccessIfNeeded() }
    }

    // MARK: - Live camera

    private var scanner: some View {
        ZStack {
            QRCameraView { payload in
                // The camera view already debounces to a single callback; just
                // forward and close.
                onScan(payload)
                dismiss()
            }
            .ignoresSafeArea()

            reticle

            VStack {
                Spacer()
                Text("scan.hint")
                    .font(.callout)
                    .foregroundStyle(.white)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 12)
                    .background(.black.opacity(0.55), in: Capsule())
                    .padding(.bottom, 48)
            }
        }
    }

    /// A simple square framing guide centered on screen.
    private var reticle: some View {
        RoundedRectangle(cornerRadius: 16)
            .stroke(.white.opacity(0.9), lineWidth: 3)
            .frame(width: 240, height: 240)
            .accessibilityHidden(true)
    }

    // MARK: - Failure states

    private var deniedNotice: some View {
        noticeStack(
            systemImage: "lock.slash",
            title: "scan.denied.title",
            message: "scan.denied.message",
        ) {
            Button("scan.openSettings") {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            }
            .buttonStyle(.borderedProminent)
            .tint(AppTheme.accent)
        }
    }

    private var unavailableNotice: some View {
        noticeStack(
            systemImage: "camera.metering.unknown",
            title: "scan.unavailable.title",
            message: "scan.unavailable.message",
        ) { EmptyView() }
    }

    private func noticeStack(
        systemImage: String,
        title: LocalizedStringKey,
        message: LocalizedStringKey,
        @ViewBuilder action: () -> some View,
    ) -> some View {
        VStack(spacing: 16) {
            Image(systemName: systemImage)
                .font(.system(size: 44))
                .foregroundStyle(.white.opacity(0.85))
            Text(title)
                .font(.headline)
                .foregroundStyle(.white)
            Text(message)
                .font(.callout)
                .foregroundStyle(.white.opacity(0.75))
                .multilineTextAlignment(.center)
            action()
        }
        .padding(32)
    }

    // MARK: - Permission

    private func requestAccessIfNeeded() async {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            status = cameraAvailable ? .authorized : .unavailable
        case .notDetermined:
            let granted = await AVCaptureDevice.requestAccess(for: .video)
            status = granted ? (cameraAvailable ? .authorized : .unavailable) : .denied
        case .denied, .restricted:
            status = .denied
        @unknown default:
            status = .denied
        }
    }

    /// Whether the device actually has a capture device to scan with (e.g. the
    /// simulator reports authorized but has no camera).
    private var cameraAvailable: Bool {
        AVCaptureDevice.default(for: .video) != nil
    }

    private enum CameraStatus {
        case checking, authorized, denied, unavailable
    }
}

/// `UIViewControllerRepresentable` bridge around an `AVCaptureSession` configured
/// to detect QR codes. Emits the payload of the first code it sees exactly once
/// (the controller stops the session after the first hit), so the SwiftUI layer
/// doesn't have to debounce.
private struct QRCameraView: UIViewControllerRepresentable {
    let onFound: (String) -> Void

    func makeUIViewController(context _: Context) -> QRCaptureController {
        let controller = QRCaptureController()
        controller.onFound = onFound
        return controller
    }

    func updateUIViewController(_ controller: QRCaptureController, context _: Context) {
        controller.onFound = onFound
    }
}

/// Owns the capture session lifecycle and the preview layer. Starts/stops the
/// session with the view's appearance and tears it down on the way out.
private final class QRCaptureController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onFound: ((String) -> Void)?

    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?
    /// Work queue for the (blocking) `startRunning` / `stopRunning` calls.
    private let sessionQueue = DispatchQueue(label: "com.tangzixiang.shadowvpn.qr-session")
    /// Guards against forwarding more than one payload.
    private var didFind = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configureSession()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        startRunning()
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        sessionQueue.async { [session] in
            if session.isRunning { session.stopRunning() }
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }

    private func configureSession() {
        guard
            let device = AVCaptureDevice.default(for: .video),
            let input = try? AVCaptureDeviceInput(device: device),
            session.canAddInput(input)
        else { return }

        session.beginConfiguration()
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else {
            session.commitConfiguration()
            return
        }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        // Restrict to QR after adding the output (the list of available types is
        // only populated once the output is attached to the session).
        output.metadataObjectTypes = output.availableMetadataObjectTypes.contains(.qr)
            ? [.qr]
            : output.availableMetadataObjectTypes
        session.commitConfiguration()

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
        self.preview = preview
    }

    private func startRunning() {
        sessionQueue.async { [session] in
            if !session.isRunning { session.startRunning() }
        }
    }

    // MARK: AVCaptureMetadataOutputObjectsDelegate

    /// `nonisolated` to satisfy the (non-isolated) delegate requirement from this
    /// `@MainActor` controller; the output was configured to deliver on `.main`,
    /// so we can synchronously assume main-actor isolation to touch UIKit state.
    nonisolated func metadataOutput(
        _: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from _: AVCaptureConnection,
    ) {
        guard
            let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
            object.type == .qr,
            let payload = object.stringValue,
            !payload.isEmpty
        else { return }
        MainActor.assumeIsolated { handle(payload) }
    }

    /// Forward the first decoded payload exactly once, then stop the session.
    private func handle(_ payload: String) {
        guard !didFind else { return }
        didFind = true
        AudioServicesPlaySystemSound(SystemSoundID(kSystemSoundID_Vibrate))
        sessionQueue.async { [session] in
            if session.isRunning { session.stopRunning() }
        }
        onFound?(payload)
    }
}
