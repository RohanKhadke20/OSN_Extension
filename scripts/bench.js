#!/usr/bin/env node

/**
 * OSN Guard - Core Performance Benchmark Suite
 * Zero-dependency throughput & latency benchmark for core security engines:
 * - URL Safety Analyzer (ops/sec, mean ms)
 * - PII Leak Detector & Masker (ops/sec, mean ms)
 * - Scam & Fraud Content Analyzer (ops/sec, mean ms)
 */

const { performance } = require("node:perf_hooks");
const urlAnalyzer = require("../core/url-analyzer.js");
const piiAnalyzer = require("../core/pii-analyzer.js");
const scamAnalyzer = require("../core/scam-analyzer.js");

function runBenchmark(name, fn, iterations = 5000) {
  // Warm-up run
  for (let i = 0; i < Math.min(iterations * 0.1, 200); i++) {
    fn(i);
  }

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    fn(i);
  }
  const totalMs = performance.now() - start;
  const opsPerSec = Math.round((iterations / (totalMs / 1000)));
  const avgMs = (totalMs / iterations).toFixed(4);

  return {
    name,
    iterations,
    totalMs: totalMs.toFixed(2),
    opsPerSec,
    avgMs
  };
}

function runAllBenchmarks() {
  console.log("==================================================");
  console.log(" OSN Guard - Core Performance Benchmark Suite");
  console.log("==================================================");

  const sampleUrls = [
    "https://www.google.com/search?q=cybersecurity+best+practices",
    "https://twitter.com/user/status/123456789",
    "http://win-iphone-now.xyz/claim/gift",
    "https://xn--pypal-4ve.com/account/verify",
    "http://0177.0.0.1/admin-panel",
    "https://bit.ly/3xY123",
    "https://tinyurl.com/account-verify",
    "data:text/html;base64,PHNjcmlwdD4=",
    "https://www.google.com/url?q=https://malicious.com"
  ];

  const sampleTexts = [
    "Contact support at alice.smith@enterprise.org or call +1 (555) 234-5678 regarding invoice #9921.",
    "Please send payment to 4532 1234 5678 9010 (exp 12/28) or verify SSN 123-45-6789 immediately.",
    "Your IBAN DE89 3704 0044 0532 0130 00 has been verified. API token: ghp_1234567890abcdef1234567890abcdef1234.",
    "Just sharing a wonderful sunset photo from our weekend trip to the mountains with friends!"
  ];

  const customPiiRules = [
    { name: "Employee Code", pattern: "\\bEMP-\\d{5}\\b", severity: "warning" },
    { name: "Support Ticket", pattern: "\\bTCK-[A-Z]{3}-\\d{4}\\b", severity: "warning" }
  ];

  const sampleScamPosts = [
    "Double your bitcoin instantly! Send ETH to our wallet address for 2x return in next 24 hours.",
    "Urgent: Unusual activity detected on your profile. Reset credentials now or account will be suspended.",
    "You seem so kind! Let's move to WhatsApp my dear, I rarely check this app.",
    "Your Geek Squad renewal has been processed. Charged your account $399.99. Call to cancel subscription.",
    "Hi mom, I dropped my phone in water and lost my phone this is my new number. Need urgent money.",
    "Just finished reading an inspiring book on software architecture and design patterns!"
  ];

  const results = [];

  // 1. URL Analyzer Benchmark
  const urlBench = runBenchmark("URL Safety Analyzer", (i) => {
    const url = sampleUrls[i % sampleUrls.length];
    urlAnalyzer.analyzeUrlSafety(url);
  }, 10000);
  results.push(urlBench);

  // 2. PII Detection Benchmark
  const piiDetectBench = runBenchmark("PII Detection Engine", (i) => {
    const text = sampleTexts[i % sampleTexts.length];
    piiAnalyzer.detectPii(text, customPiiRules);
  }, 5000);
  results.push(piiDetectBench);

  // 3. PII Masking Benchmark
  const piiMaskBench = runBenchmark("PII Masking & Redaction", (i) => {
    const text = sampleTexts[i % sampleTexts.length];
    piiAnalyzer.maskPii(text, customPiiRules);
  }, 5000);
  results.push(piiMaskBench);

  // 4. Scam Analyzer Benchmark
  const scamBench = runBenchmark("Scam & Fraud Classifier", (i) => {
    const post = sampleScamPosts[i % sampleScamPosts.length];
    scamAnalyzer.detectScamContent(post);
  }, 15000);
  results.push(scamBench);

  // Print results table
  console.log("");
  console.log(
    "Benchmark".padEnd(28) +
    "Iterations".padEnd(14) +
    "Time (ms)".padEnd(14) +
    "Throughput".padEnd(18) +
    "Avg Latency"
  );
  console.log("-".repeat(85));

  for (const r of results) {
    console.log(
      r.name.padEnd(28) +
      String(r.iterations).padEnd(14) +
      (r.totalMs + " ms").padEnd(14) +
      (r.opsPerSec.toLocaleString() + " ops/s").padEnd(18) +
      (r.avgMs + " ms/op")
    );
  }
  console.log("==================================================");

  // Verify performance budgets
  const urlBudgetMet = urlBench.opsPerSec >= 5000;
  const piiBudgetMet = piiDetectBench.opsPerSec >= 1000;
  const scamBudgetMet = scamBench.opsPerSec >= 10000;

  if (!urlBudgetMet || !piiBudgetMet || !scamBudgetMet) {
    console.error("❌ Performance budget not met!");
    process.exit(1);
  }

  console.log("✔ All performance budgets satisfied.");
  return results;
}

if (require.main === module) {
  runAllBenchmarks();
}

module.exports = { runBenchmark, runAllBenchmarks };
