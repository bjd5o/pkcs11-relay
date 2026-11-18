// The simulator end-to-end test, run by tests/sim-e2e.sh: a real relay on the host, the app with
// relay-ffi's software test card, and `relay-test-approver sim-client` on the host as the client.
// The test plays the person: enroll, approve the pairing, approve the decrypt with the PIN.

import XCTest

final class SimEndToEnd: XCTestCase {
    func testEnrollPairAndApproveADecrypt() throws {
        let env = ProcessInfo.processInfo.environment
        guard env["RELAY_TEST_LINK"] != nil, env["RELAY_TEST_CARD"] != nil else {
            throw XCTSkip("run by tests/sim-e2e.sh")
        }
        let pin = env["RELAY_TEST_PIN"] ?? "123456"
        continueAfterFailure = false
        let app = XCUIApplication()
        // The setup link arrives as if scanned; test roots and a keyserver stand-in come along.
        for k in ["RELAY_TEST_LINK", "RELAY_TEST_CARD", "RELAY_TEST_ROOTS", "RELAY_TEST_KEYSERVER"] {
            app.launchEnvironment[k] = env[k]
        }
        app.launch()

        // Setup: the checked link is shown; the person reads it, scrolls down and confirms.
        let device = element(app, "setup-device")
        if !device.waitForExistence(timeout: 60) {
            // Show what the app shows instead (an error alert, usually).
            XCTFail("the setup link was not accepted:\n\(app.debugDescription)")
            return
        }
        let confirm = app.buttons["confirm-setup"]
        for _ in 0..<6 where !confirm.exists || !confirm.isHittable {
            app.swipeUp()
        }
        XCTAssertTrue(confirm.waitForExistence(timeout: 10))
        confirm.tap()

        // Enroll: PIN, then the (software) tap.
        let status = app.tabBars.buttons["Status"]
        XCTAssertTrue(status.waitForExistence(timeout: 60), "the app connected to the relay")
        status.tap()
        // First tap: read the keys, no PIN.
        let read = app.buttons["read-yubikey"]
        XCTAssertTrue(read.waitForExistence(timeout: 10))
        read.tap()
        let pinField = app.secureTextFields["pin"]
        XCTAssertTrue(pinField.waitForExistence(timeout: 10))
        pinField.tap()
        pinField.typeText(pin)
        app.buttons["enroll"].tap()
        XCTAssertTrue(element(app, "attestation-valid").waitForExistence(timeout: 60), "enrolled")

        // Approve the client's pairing for the unseal key.
        app.tabBars.buttons["Requests"].tap()
        let pairing = element(app, "pairing-openbao-pi5")
        XCTAssertTrue(pairing.waitForExistence(timeout: 300), "the client asked to pair")
        pairing.tap()
        let key = app.switches["key-openbao-unseal"]
        XCTAssertTrue(key.waitForExistence(timeout: 10))
        key.switches.firstMatch.exists ? key.switches.firstMatch.tap() : key.tap()
        let approvePairing = app.buttons["approve-pairing"]
        XCTAssertTrue(approvePairing.waitForExistence(timeout: 10))
        XCTAssertTrue(approvePairing.isEnabled, "a key was chosen")
        approvePairing.tap()

        // Approve the decrypt with the PIN.
        let request = element(app, "request-openbao-unseal")
        XCTAssertTrue(request.waitForExistence(timeout: 300), "the client's decrypt arrived")
        request.tap()
        // The PIN comes after the request details: scroll down to it, as a person would.
        let pin2 = app.secureTextFields["pin"]
        for _ in 0..<6 where !pin2.exists || !pin2.isHittable {
            app.swipeUp()
        }
        XCTAssertTrue(pin2.waitForExistence(timeout: 10))
        pin2.tap()
        pin2.typeText(pin)
        let approve = app.buttons["approve"]
        for _ in 0..<3 where !approve.isHittable {
            app.swipeUp()
        }
        approve.tap()
        XCTAssertTrue(request.waitForNonExistence(timeout: 60), "approved and gone from the list")
    }

    private func element(_ app: XCUIApplication, _ id: String) -> XCUIElement {
        app.descendants(matching: .any)[id].firstMatch
    }
}
