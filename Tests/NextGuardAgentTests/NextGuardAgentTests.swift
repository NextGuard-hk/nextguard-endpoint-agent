import XCTest

final class NextGuardAgentTests: XCTestCase {

  func testDLPPatternCreditCard() {
    let pattern = "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\\b"
    let regex = try? NSRegularExpression(pattern: pattern)
    XCTAssertNotNil(regex, "Credit card regex should compile")
  }

  func testDangerousFileExtensions() {
    let dangerous = ["exe", "bat", "cmd", "scr", "msi", "dll", "dmg", "pkg"]
    XCTAssertFalse(dangerous.contains("pdf"))
    XCTAssertTrue(dangerous.contains("exe"))
  }

  func testConfigParsing() {
    let json = "{\"version\":\"1.0.0\"}"
    let data = json.data(using: .utf8)!
    let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    XCTAssertNotNil(parsed)
    XCTAssertEqual(parsed?["version"] as? String, "1.0.0")
  }
}
