const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { isReviewPromptEligible } = require("../popup/popup.js");

describe("Ethical Review Prompt Eligibility (popup/popup.js)", () => {
  const NOW = 1750000000000;
  const ONE_DAY_MS = 24 * 60 * 60 * 1000;
  const THREE_DAYS_MS = 3 * ONE_DAY_MS;
  const FOURTEEN_DAYS_MS = 14 * ONE_DAY_MS;

  it("rejects null, undefined, or non-object storage data", () => {
    assert.equal(isReviewPromptEligible(null).eligible, false);
    assert.equal(isReviewPromptEligible(undefined).eligible, false);
    assert.equal(isReviewPromptEligible("invalid").eligible, false);
  });

  it("rejects when usage thresholds (5 threats or 50 links) are not met", () => {
    const data = {
      installedAt: NOW - (4 * ONE_DAY_MS), // 4 days ago (valid)
      stats: { threatsDetected: 4, linksScanned: 49 },
      reviewState: { dismissed: false, completed: false, lastPromptedAt: 0 }
    };

    const res = isReviewPromptEligible(data, NOW);
    assert.equal(res.eligible, false);
    assert.match(res.reason, /Usage threshold not met/);
  });

  it("accepts when at least 5 threats are detected even if links scanned < 50", () => {
    const data = {
      installedAt: NOW - (4 * ONE_DAY_MS),
      stats: { threatsDetected: 5, linksScanned: 10 },
      reviewState: { dismissed: false, completed: false, lastPromptedAt: 0 }
    };

    const res = isReviewPromptEligible(data, NOW);
    assert.equal(res.eligible, true);
  });

  it("accepts when at least 50 links are scanned even if threats detected === 0", () => {
    const data = {
      installedAt: NOW - (4 * ONE_DAY_MS),
      stats: { threatsDetected: 0, linksScanned: 50 },
      reviewState: { dismissed: false, completed: false, lastPromptedAt: 0 }
    };

    const res = isReviewPromptEligible(data, NOW);
    assert.equal(res.eligible, true);
  });

  it("rejects when extension was installed less than 3 days ago", () => {
    const data = {
      installedAt: NOW - (2 * ONE_DAY_MS), // 2 days ago (< 3 days)
      stats: { threatsDetected: 10, linksScanned: 100 },
      reviewState: { dismissed: false, completed: false, lastPromptedAt: 0 }
    };

    const res = isReviewPromptEligible(data, NOW);
    assert.equal(res.eligible, false);
    assert.match(res.reason, /Minimum install age of 3 days not met/);
  });

  it("rejects when installedAt timestamp is missing, zero, or negative", () => {
    const data1 = {
      installedAt: 0,
      stats: { threatsDetected: 10, linksScanned: 100 },
      reviewState: { dismissed: false, completed: false, lastPromptedAt: 0 }
    };
    const data2 = {
      installedAt: -500,
      stats: { threatsDetected: 10, linksScanned: 100 }
    };

    assert.equal(isReviewPromptEligible(data1, NOW).eligible, false);
    assert.equal(isReviewPromptEligible(data2, NOW).eligible, false);
  });

  it("accepts when extension was installed exactly 3 days ago", () => {
    const data = {
      installedAt: NOW - THREE_DAYS_MS,
      stats: { threatsDetected: 5, linksScanned: 50 },
      reviewState: { dismissed: false, completed: false, lastPromptedAt: 0 }
    };

    const res = isReviewPromptEligible(data, NOW);
    assert.equal(res.eligible, true);
  });

  it("rejects if user previously dismissed the review prompt", () => {
    const data = {
      installedAt: NOW - (10 * ONE_DAY_MS),
      stats: { threatsDetected: 8, linksScanned: 200 },
      reviewState: { dismissed: true, completed: false, lastPromptedAt: 0 }
    };

    const res = isReviewPromptEligible(data, NOW);
    assert.equal(res.eligible, false);
    assert.match(res.reason, /previously dismissed/);
  });

  it("rejects if user already submitted a review", () => {
    const data = {
      installedAt: NOW - (10 * ONE_DAY_MS),
      stats: { threatsDetected: 8, linksScanned: 200 },
      reviewState: { dismissed: false, completed: true, lastPromptedAt: 0 }
    };

    const res = isReviewPromptEligible(data, NOW);
    assert.equal(res.eligible, false);
    assert.match(res.reason, /previously completed/);
  });

  it("rejects if deferred and prompted within the 14-day cooldown window", () => {
    const data = {
      installedAt: NOW - (30 * ONE_DAY_MS),
      stats: { threatsDetected: 10, linksScanned: 300 },
      reviewState: {
        dismissed: false,
        completed: false,
        lastPromptedAt: NOW - (7 * ONE_DAY_MS) // prompted 7 days ago (< 14 days)
      }
    };

    const res = isReviewPromptEligible(data, NOW);
    assert.equal(res.eligible, false);
    assert.match(res.reason, /Frequency cooldown active/);
  });

  it("accepts if deferred and the 14-day cooldown period has elapsed", () => {
    const data = {
      installedAt: NOW - (30 * ONE_DAY_MS),
      stats: { threatsDetected: 10, linksScanned: 300 },
      reviewState: {
        dismissed: false,
        completed: false,
        lastPromptedAt: NOW - FOURTEEN_DAYS_MS // prompted exactly 14 days ago
      }
    };

    const res = isReviewPromptEligible(data, NOW);
    assert.equal(res.eligible, true);
  });

  it("handles missing reviewState by treating as unprompted", () => {
    const data = {
      installedAt: NOW - (5 * ONE_DAY_MS),
      stats: { threatsDetected: 6, linksScanned: 75 }
      // reviewState omitted
    };

    const res = isReviewPromptEligible(data, NOW);
    assert.equal(res.eligible, true);
  });
});
