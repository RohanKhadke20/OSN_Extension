const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { runBenchmark, runAllBenchmarks } = require("../scripts/bench.js");

describe("Core Performance Benchmark Suite", () => {
  it("executes custom benchmark function and computes accurate metrics", () => {
    let callCount = 0;
    const result = runBenchmark("Math.sqrt Benchmark", (i) => {
      callCount++;
      Math.sqrt(i * 12345);
    }, 500);

    assert.equal(result.name, "Math.sqrt Benchmark");
    assert.equal(result.iterations, 500);
    assert.ok(parseFloat(result.totalMs) >= 0);
    assert.ok(result.opsPerSec > 0);
    assert.ok(parseFloat(result.avgMs) >= 0);
    assert.ok(callCount >= 500);
  });

  it("exports runAllBenchmarks which returns all 4 benchmark suites", () => {
    const results = runAllBenchmarks();
    assert.equal(Array.isArray(results), true);
    assert.equal(results.length, 4);

    const names = results.map(r => r.name);
    assert.ok(names.includes("URL Safety Analyzer"));
    assert.ok(names.includes("PII Detection Engine"));
    assert.ok(names.includes("PII Masking & Redaction"));
    assert.ok(names.includes("Scam & Fraud Classifier"));

    for (const r of results) {
      assert.ok(r.opsPerSec > 1000, `Expected >1000 ops/sec for ${r.name}, got ${r.opsPerSec}`);
    }
  });
});
