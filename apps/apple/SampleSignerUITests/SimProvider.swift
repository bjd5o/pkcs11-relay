// The provider's simulator test, run by tests/sim-provider.sh: a real relay and an auto-approving
// relay-test-approver on the host, the sample app in the simulator. The test imports the
// fixture config, waits until the pairing is approved and the keys are listed, signs a message
// with sign-ec and checks that the app verified the signature.

import XCTest

final class SimProvider: XCTestCase {
    func testImportPairSignAndVerify() throws {
        let env = ProcessInfo.processInfo.environment
        guard let dir = env["SAMPLE_SIGNER_IMPORT"] else {
            throw XCTSkip("run by tests/sim-provider.sh")
        }
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchEnvironment["SAMPLE_SIGNER_IMPORT"] = dir
        app.launch()

        // The first listing registers the client and logs the pairing code; the test approver
        // approves the pairing, and a refresh then lists the keys.
        let key = app.buttons["key-softcard-a-sign-ec"]
        let refresh = app.buttons["refresh"]
        let deadline = Date().addingTimeInterval(180)
        while !key.exists && Date() < deadline {
            if refresh.exists && refresh.isHittable { refresh.tap() }
            _ = key.waitForExistence(timeout: 3)
        }
        XCTAssertTrue(key.exists, "paired and the keys listed:\n\(app.debugDescription)")
        key.tap()

        let message = app.textFields["message"]
        scrollTo(message, in: app)
        message.tap()
        message.typeText(" from the simulator")
        let sign = app.buttons["sign"]
        scrollTo(sign, in: app)
        XCTAssertTrue(sign.isEnabled, "a key is selected")
        sign.tap()

        // C_Sign blocks until the test approver answers; the app then verifies in Swift.
        let verified = app.descendants(matching: .any)["signature-verified"].firstMatch
        if !verified.waitForExistence(timeout: 120) {
            XCTFail("the signature was not verified:\n\(app.debugDescription)")
        }
    }

    private func scrollTo(_ e: XCUIElement, in app: XCUIApplication) {
        for _ in 0..<6 where !e.exists || !e.isHittable {
            app.swipeUp()
        }
        XCTAssertTrue(e.waitForExistence(timeout: 10), "\(e) on screen")
    }
}
