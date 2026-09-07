const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

/**
 * Score calculation reference engine extracted from popup dashboard
 */
function computeScore(threats = [], shields = { pii: true, url: true, content: true, security: true }, isWhitelisted = false) {
  if (isWhitelisted) {
    return { score: 100, status: "Domain Whitelisted" };
  }

  const criticalThreats = threats.filter(t => t.severity === "critical").length;
  const warningThreats = threats.filter(t => t.severity === "warning").length;

  let score = 100;
  score -= (criticalThreats * 25);
  score -= (warningThreats * 10);

  let activeShieldsCount = 0;
  const shieldKeys = ["pii", "url", "content", "security"];
  shieldKeys.forEach(k => {
    if (!shields[k]) {
      score -= 5;
    } else {
      activeShieldsCount++;
    }
  });

  score = Math.max(0, Math.min(100, score));

  let status = "";
  if (activeShieldsCount === 0) {
    status = "Protection Offline";
  } else if (score >= 90) {
    status = "Connection Secure";
  } else if (score >= 60) {
    status = "Caveats Found";
  } else {
    status = "High Risk Detected";
  }

  return { score, status, criticalThreats, warningThreats, activeShieldsCount };
}

describe("Dashboard Score & Status Engine", () => {
  it("returns 100% and Connection Secure for pristine page with all shields active", () => {
    const res = computeScore([], { pii: true, url: true, content: true, security: true });
    assert.equal(res.score, 100);
    assert.equal(res.status, "Connection Secure");
  });

  it("deducts 25 points per critical threat", () => {
    const threats = [{ severity: "critical" }];
    const res = computeScore(threats);
    assert.equal(res.score, 75);
    assert.equal(res.status, "Caveats Found");

    const threats2 = [{ severity: "critical" }, { severity: "critical" }];
    const res2 = computeScore(threats2);
    assert.equal(res2.score, 50);
    assert.equal(res2.status, "High Risk Detected");
  });

  it("deducts 10 points per warning threat", () => {
    const threats = [{ severity: "warning" }];
    const res = computeScore(threats);
    assert.equal(res.score, 90);
    assert.equal(res.status, "Connection Secure");

    const threats3 = [{ severity: "warning" }, { severity: "warning" }, { severity: "warning" }];
    const res3 = computeScore(threats3);
    assert.equal(res3.score, 70);
    assert.equal(res3.status, "Caveats Found");
  });

  it("deducts 5 points per disabled shield", () => {
    const shields = { pii: true, url: true, content: false, security: false };
    const res = computeScore([], shields);
    assert.equal(res.score, 90); // 100 - 10
    assert.equal(res.status, "Connection Secure");
  });

  it("reports Protection Offline when all shields are disabled", () => {
    const allDisabled = { pii: false, url: false, content: false, security: false };
    const res = computeScore([], allDisabled);
    assert.equal(res.status, "Protection Offline");
    assert.equal(res.activeShieldsCount, 0);
  });

  it("clamps minimum score to 0 regardless of overwhelming threats", () => {
    const overwhelming = Array(10).fill({ severity: "critical" });
    const res = computeScore(overwhelming);
    assert.equal(res.score, 0);
    assert.equal(res.status, "High Risk Detected");
  });

  it("always returns 100 and Domain Whitelisted status for whitelisted domains", () => {
    const threats = [{ severity: "critical" }, { severity: "critical" }];
    const res = computeScore(threats, { pii: true, url: true, content: true, security: true }, true);
    assert.equal(res.score, 100);
    assert.equal(res.status, "Domain Whitelisted");
  });
});
