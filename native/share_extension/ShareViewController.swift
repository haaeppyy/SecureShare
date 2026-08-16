import Cocoa

/// macOS Share Extension for SecureShare.
///
/// Appears in Finder's right-click -> Share menu. Pulls the selected file
/// URLs out of the share context, hands them to the SecureShare app via
/// the `secureshare://send?files=...` URL scheme, and completes the
/// request. The app decides what to do (device picker / send).
final class ShareViewController: NSObject, NSExtensionRequestHandling {

    func beginRequest(with context: NSExtensionContext) {
        var paths: [String] = []
        for item in context.inputItems {
            guard let item = item as? NSExtensionItem else { continue }
            for provider in item.attachments ?? [] {
                if let url = loadURL(from: provider) {
                    paths.append(url.path)
                }
            }
        }
        if !paths.isEmpty {
            let encoded = paths.joined(separator: "\n")
                .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
            if let url = URL(string: "secureshare://send?files=\(encoded)") {
                NSWorkspace.shared.open(url)
            }
        }
        context.completeRequest(returningItems: nil, completionHandler: nil)
    }

    /// Synchronously loads a file URL from an item provider. The extension
    /// process is torn down right after completeRequest, so we cannot rely
    /// on the async completion arriving later.
    private func loadURL(from provider: NSItemProvider) -> URL? {
        let identifier: String
        if provider.hasItemConformingToTypeIdentifier("public.file-url") {
            identifier = "public.file-url"
        } else if provider.hasItemConformingToTypeIdentifier("public.url") {
            identifier = "public.url"
        } else {
            return nil
        }
        let semaphore = DispatchSemaphore(value: 0)
        var result: URL?
        provider.loadItem(forTypeIdentifier: identifier, options: nil) { item, _ in
            if let url = item as? URL {
                result = url
            } else if let data = item as? Data {
                result = URL(dataRepresentation: data, relativeTo: nil)
            }
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + 10)
        return result
    }
}