// APNs: ask for permission, hand the device token to the model, and open the Requests tab when
// a notification is tapped. The notification itself only says "1 pending request" (the relay
// sends no content); the app fetches what is waiting over its own connection.

import Foundation
import UserNotifications

#if os(iOS)
import UIKit

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        Push.start { application.registerForRemoteNotifications() }
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Push.received(token: deviceToken)
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        NSLog("relay-push: registration failed: %@", error.localizedDescription)
    }
}
#elseif os(macOS)
import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        UNUserNotificationCenter.current().delegate = self
        Push.start { NSApplication.shared.registerForRemoteNotifications() }
    }

    func application(_ application: NSApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Push.received(token: deviceToken)
    }

    func application(_ application: NSApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        NSLog("relay-push: registration failed: %@", error.localizedDescription)
    }

    /// The window can close; the app stays in the menu bar and keeps polling.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}
#endif

extension AppDelegate {
    /// A notification tapped: show what is waiting.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
    ) async {
        await MainActor.run { NotificationCenter.default.post(name: Push.opened, object: nil) }
    }

    /// While the app is in front, the inbox already shows the request; just a sound.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.sound]
    }
}

enum Push {
    static let token = Notification.Name("relay.push.token")
    static let opened = Notification.Name("relay.push.opened")

    static func start(register: @escaping @MainActor () -> Void) {
        #if RELAY_TEST_CARD
        // The simulator end-to-end test long-polls; a permission prompt would cover the app.
        if ProcessInfo.processInfo.environment["RELAY_TEST_CARD"] != nil { return }
        #endif
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error { NSLog("relay-push: %@", error.localizedDescription) }
            guard granted else { return }
            Task { @MainActor in register() }
        }
    }

    static func received(token: Data) {
        let hex = token.map { String(format: "%02x", $0) }.joined()
        NotificationCenter.default.post(name: Push.token, object: hex)
    }
}
