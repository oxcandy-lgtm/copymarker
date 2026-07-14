#!/usr/bin/env node
// Public safety scanner tests - using node:test
// NO violation patterns in source - ALL constructed at runtime

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const SCANNER = "./scripts/public-safety.mjs";
const ROOT = process.cwd();

function runScanner(args, env = {}) {
    const result = spawnSync("node", [SCANNER, ...args], {
        cwd: ROOT,
        encoding: "utf8",
        timeout: 30000,
        env: { ...process.env, ...env }
    });
    return {
        code: result.status ?? 1,
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? ""
    };
}

function assertFails(result, expectedCode, message) {
    assert.strictEqual(result.code, expectedCode, message);
}

function assertContains(text, substring, message) {
    assert.ok(text.includes(substring), message);
}

function assertNotContains(text, substring, message) {
    assert.ok(!text.includes(substring), message);
}

function makeTempDir() {
    return mkdtempSync(join(tmpdir(), "copymarker-test-"));
}

function cleanupTempDir(dir) {
    try { rmSync(dir, { recursive: true, force: true }); } catch (e) {}
}

// Runtime violation pattern builders - NO patterns in source
function bpk(d) {
    const pk = ["-----BEGIN ", "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...\n-----END ", "PRIVATE KEY-----"].join("");
    writeFileSync(join(d, "key.pem"), pk);
}
function bat(d) { const s = "sk_live_" + "a".repeat(24); writeFileSync(join(d, "config.js"), `const apiKey = "${s}";`); }
function bah(d) { writeFileSync(join(d, "request.http"), "Authorization: Bearer " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."); }
function bck(d) { writeFileSync(join(d, "cookies.txt"), "Cookie: " + "session=abc123; user_id=456; token=xyz789"); }
function bem(d) { writeFileSync(join(d, "contact.md"), "Contact: " + "john.doe@company.com for support."); }
function bip4(d) { writeFileSync(join(d, "server.js"), "const server = '" + "192.168.1.100" + "';"); }
function bip6(d) { writeFileSync(join(d, "server.js"), "const server = '" + "2001:db8::1:2:3" + "';"); }
function bup(d) { writeFileSync(join(d, "config.json"), '{"dataDir": "/home/user/.config/app/data"}'); }
function bwp(d) { writeFileSync(join(d, "config.json"), '{"dataDir": "C:\\Users\\user\\AppData\\Local\\App"}'); }
function bbp(d) { writeFileSync(join(d, "profile.txt"), "Profile: " + "/home/user/.config/chrome/Default"); }
function bwh(d) { const url = "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X".repeat(24); writeFileSync(join(d, "webhook.json"), `{"url": "${url}"}`); }
function bdn(d) { writeFileSync(join(d, "private-denylist.txt"), "INTERNAL_PROJECT_X\nSECRET_CODENAME"); writeFileSync(join(d, "internal.md"), "Project: INTERNAL_PROJECT_X"); }
function bft(d) { writeFileSync(join(d, "network.js"), "fet" + "ch('https://api.example.com/data')"); }
function bxh(d) { writeFileSync(join(d, "xhr.js"), "const xhr = new XMLHtt" + "pRequest();"); }
function bws(d) { writeFileSync(join(d, "ws.js"), "const ws = new WebS" + "ocket('wss://api.example.com')"); }
function bes(d) { writeFileSync(join(d, "sse.js"), "const es = new EventS" + "ource('https://api.example.com/events')"); }
function bbn(d) { writeFileSync(join(d, "beacon.js"), "navigator.sendBe" + "acon('/analytics', data)"); }
function bsm(d) { writeFileSync(join(d, "bundle.js.map"), '{"version":3,"sources":["/home/user/project/src/main.ts"]}'); }
function brt(d) { writeFileSync(join(d, "root-file.txt"), `secret = "sk_live_${"a".repeat(24)}"`); }

// Negative test builders
function bex(d) { writeFileSync(join(d, "contact.md"), "Contact: user@example.com for support."); }
function br4(d) { writeFileSync(join(d, "docs.md"), "Test server: 192.0.2.1"); }
function br6(d) { writeFileSync(join(d, "docs.md"), "Test server: 2001:db8::1"); }
function brd(d) { writeFileSync(join(d, "config.json"), '{"apiKey": "<redacted>"}'); }
function bns(d) { writeFileSync(join(d, "app.js"), 'function hello() { return "world"; }'); }
function bpd(d) { writeFileSync(join(d, "policy.md"), "## Rules\n- PRIVATE_KEY_BLOCK\n- API_TOKEN\n- AUTHORIZATION_HEADER"); }
function bsr(d) { writeFileSync(join(d, "scanner.js"), "const RULES = ['PRIVATE_KEY_BLOCK', 'API_TOKEN'];"); }
function bsv(d, s) { writeFileSync(join(d, "secret.js"), `const secret = "${s}";`); }
function bdl(d) { writeFileSync(join(d, "private-denylist.txt"), "INTERNAL_PROJECT_X"); writeFileSync(join(d, "internal.md"), "Project: INTERNAL_PROJECT_X"); }
function bdp(d) { writeFileSync(join(d, "private-denylist.txt"), "INTERNAL_PROJECT_X"); writeFileSync(join(d, "internal.md"), "Project: INTERNAL_PROJECT_X"); }
function bsm2(d) { writeFileSync(join(d, "bundle.js.map"), '{"version":3,"sources":["/home/user/project/src/main.ts"]}'); }
function bsr2(d) { writeFileSync(join(d, "bundle.js.map"), '{"version":3,"sourceRoot":"/home/user/project/","sources":["src/main.ts"]}'); }
function brtf(d) { writeFileSync(join(d, "root-file.txt"), `secret = "sk_live_${"a".repeat(24)}"`); }
function bexm(d) { writeFileSync(join(d, "contact.md"), "Contact: user@example.com for support."); }
function br4v(d) { writeFileSync(join(d, "docs.md"), "Test server: 192.0.2.1"); }
function br6v(d) { writeFileSync(join(d, "docs.md"), "Test server: 2001:db8::1"); }
function brdd(d) { writeFileSync(join(d, "config.json"), '{"apiKey": "<redacted>"}'); }
function bnsf(d) { writeFileSync(join(d, "app.js"), 'function hello() { return "world"; }'); }
function bpex(d) { writeFileSync(join(d, "policy.md"), "Allowed domains: example.com, example.org"); }
function bssc(d) { writeFileSync(join(d, "scanner.js"), "const RULES = ['PRIVATE_KEY_BLOCK', 'API_TOKEN'];"); }
function bsv1(d) { writeFileSync(join(d, "secret.js"), `const secret = "${"sk_live_" + "a".repeat(24)}";`); }
function bsv2(d) { writeFileSync(join(d, "secret.js"), `const secret = "${"sk_live_" + "b".repeat(24)}";`); }
function bdlf(d) { writeFileSync(join(d, "private-denylist.txt"), "test.*pattern"); writeFileSync(join(d, "secret.txt"), "test_pattern"); }
function bspf(d) { writeFileSync(join(d, "secret.txt"), "test_pattern"); }
function bmxv(d) { const s = "sk_live_" + "a".repeat(24); writeFileSync(join(d, "mixed.js"), `const a = "<redacted>"; const b = "${s}";`); }
function bpex2(d) { writeFileSync(join(d, "policy.md"), "Allowed domains: example.com, example.org"); }
function bssc2(d) { writeFileSync(join(d, "scanner.js"), "const RULES = ['PRIVATE_KEY_BLOCK', 'API_TOKEN'];"); }

// ========== POSITIVE TESTS ==========
test("PRIVATE_KEY_BLOCK detected", () => { const dir = makeTempDir(); try { bpk(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Private key should exit 1"); assertContains(r.stdout + r.stderr, "PRIVATE_KEY_BLOCK", "Should report PRIVATE_KEY_BLOCK rule"); } finally { cleanupTempDir(dir); } });
test("API_TOKEN detected", () => { const dir = makeTempDir(); try { bat(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "API token should exit 1"); assertContains(r.stdout + r.stderr, "API_TOKEN", "Should report API_TOKEN rule"); } finally { cleanupTempDir(dir); } });
test("AUTHORIZATION_HEADER detected", () => { const dir = makeTempDir(); try { bah(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Auth header should exit 1"); assertContains(r.stdout + r.stderr, "AUTHORIZATION_HEADER", "Should report AUTHORIZATION_HEADER rule"); } finally { cleanupTempDir(dir); } });
test("COOKIE_HEADER detected", () => { const dir = makeTempDir(); try { bck(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Cookie header should exit 1"); assertContains(r.stdout + r.stderr, "COOKIE_HEADER", "Should report COOKIE_HEADER rule"); } finally { cleanupTempDir(dir); } });
test("NON_EXAMPLE_EMAIL detected", () => { const dir = makeTempDir(); try { bem(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Real email should exit 1"); assertContains(r.stdout + r.stderr, "NON_EXAMPLE_EMAIL", "Should report NON_EXAMPLE_EMAIL rule"); } finally { cleanupTempDir(dir); } });
test("IP_ADDRESS IPv4 detected", () => { const dir = makeTempDir(); try { bip4(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "IPv4 address should exit 1"); assertContains(r.stdout + r.stderr, "IP_ADDRESS", "Should report IP_ADDRESS rule"); } finally { cleanupTempDir(dir); } });
test("IP_ADDRESS IPv6 detected", () => { const dir = makeTempDir(); try { bip6(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "IPv6 address should exit 1"); assertContains(r.stdout + r.stderr, "IP_ADDRESS", "Should report IP_ADDRESS rule"); } finally { cleanupTempDir(dir); } });
test("UNIX_ABSOLUTE_PATH detected", () => { const dir = makeTempDir(); try { bup(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Absolute Unix path should exit 1"); assertContains(r.stdout + r.stderr, "UNIX_ABSOLUTE_PATH", "Should report UNIX_ABSOLUTE_PATH rule"); } finally { cleanupTempDir(dir); } });
test("WINDOWS_ABSOLUTE_PATH detected", () => { const dir = makeTempDir(); try { bwp(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Windows absolute path should exit 1"); assertContains(r.stdout + r.stderr, "WINDOWS_ABSOLUTE_PATH", "Should report WINDOWS_ABSOLUTE_PATH rule"); } finally { cleanupTempDir(dir); } });
test("BROWSER_PROFILE_PATH detected", () => { const dir = makeTempDir(); try { bbp(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Browser profile path should exit 1"); assertContains(r.stdout + r.stderr, "BROWSER_PROFILE_PATH", "Should report BROWSER_PROFILE_PATH rule"); } finally { cleanupTempDir(dir); } });
test("WEBHOOK_URL detected", () => { const dir = makeTempDir(); try { bwh(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Webhook URL should exit 1"); assertContains(r.stdout + r.stderr, "WEBHOOK_URL", "Should report WEBHOOK_URL rule"); } finally { cleanupTempDir(dir); } });
test("PRIVATE_DENYLIST_TERM detected", () => { const dir = makeTempDir(); try { bdn(dir); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: join(dir, "private-denylist.txt") }); assertFails(r, 1, "Private denylist term should exit 1"); assertNotContains(r.stdout + r.stderr, "INTERNAL_PROJECT_X", "Should not print private denylist term"); } finally { cleanupTempDir(dir); } });
test("RUNTIME_NETWORK_PRIMITIVE fetch detected", () => { const dir = makeTempDir(); try { bft(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Fetch usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });
test("RUNTIME_NETWORK_PRIMITIVE XMLHttpRequest detected", () => { const dir = makeTempDir(); try { bxh(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "XMLHttpRequest usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });
test("RUNTIME_NETWORK_PRIMITIVE WebSocket detected", () => { const dir = makeTempDir(); try { bws(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "WebSocket usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });
test("RUNTIME_NETWORK_PRIMITIVE EventSource detected", () => { const dir = makeTempDir(); try { bes(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "EventSource usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });
test("RUNTIME_NETWORK_PRIMITIVE sendBeacon detected", () => { const dir = makeTempDir(); try { bbn(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "sendBeacon usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });
test("SOURCE_MAP_LOCAL_PATH detected", () => { const dir = makeTempDir(); try { bsm(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Source map path should exit 1"); assertContains(r.stdout + r.stderr, "SOURCE_MAP_LOCAL_PATH", "Should report SOURCE_MAP_LOCAL_PATH rule"); } finally { cleanupTempDir(dir); } });
test("root file scan supported", () => { const dir = makeTempDir(); try { brt(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Root file should be scanned"); } finally { cleanupTempDir(dir); } });

// ========== NEGATIVE TESTS ==========
test("example.com email allowed", () => { const dir = makeTempDir(); try { bex(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Example email should be allowed"); } finally { cleanupTempDir(dir); } });
test("reserved IPv4 allowed", () => { const dir = makeTempDir(); try { br4(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Reserved documentation IPv4 should be allowed"); } finally { cleanupTempDir(dir); } });
test("reserved IPv6 allowed", () => { const dir = makeTempDir(); try { br6(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Reserved documentation IPv6 should be allowed"); } finally { cleanupTempDir(dir); } });
test("redacted marker allowed", () => { const dir = makeTempDir(); try { brd(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Redacted marker should be allowed"); } finally { cleanupTempDir(dir); } });
test("normal source allowed", () => { const dir = makeTempDir(); try { bns(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Normal source code should be allowed"); } finally { cleanupTempDir(dir); } });
test("policy document can name rule categories", () => { const dir = makeTempDir(); try { bpd(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Policy document naming rules should be allowed"); } finally { cleanupTempDir(dir); } });
test("scanner rule definitions allowed", () => { const dir = makeTempDir(); try { bsr(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Scanner rule definitions should be allowed"); } finally { cleanupTempDir(dir); } });
test("matched value absent from stdout", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "a".repeat(24); bsv(dir, s); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, s, "Should not print matched secret value in stdout/stderr"); } finally { cleanupTempDir(dir); } });
test("matched value absent from stderr", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "b".repeat(24); bsv(dir, s); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, s, "Should not print matched secret value in stderr"); } finally { cleanupTempDir(dir); } });
test("denylist term absent from output", () => { const dir = makeTempDir(); try { bdl(dir); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: join(dir, "private-denylist.txt") }); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, "INTERNAL_PROJECT_X", "Should not print private denylist term"); } finally { cleanupTempDir(dir); } });
test("denylist path absent from output", () => { const dir = makeTempDir(); try { bdp(dir); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: join(dir, "private-denylist.txt") }); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, join(dir, "private-denylist.txt"), "Should not print absolute denylist file path"); } finally { cleanupTempDir(dir); } });

// ========== METADATA AND CONTRACT TESTS ==========
test("path file mode scans file not directory", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "a".repeat(24); writeFileSync(join(dir, "file.txt"), `secret = "${s}";`); const r = runScanner(["--path", join(dir, "file.txt")]); assertFails(r, 1, "Path mode with file should work"); assertContains(r.stdout, "API_TOKEN", "Should report API_TOKEN"); assertContains(r.stdout, "file.txt:", "Should report file path"); assertNotContains(r.stdout + r.stderr, s, "Should not print secret"); } finally { cleanupTempDir(dir); } });
test("path directory mode scans directory", () => { const dir = makeTempDir(); try { brt(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Path mode with directory should work"); } finally { cleanupTempDir(dir); } });
test("read errors fail closed with sanitized error", () => { const dir = makeTempDir(); try {
    const d = join(dir, "private-denylist.txt");
    mkdirSync(d);  // Create directory instead of file - will cause read error
    writeFileSync(join(dir, "test.txt"), "normal content");
    const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: d });
    assertFails(r, 1, "Unreadable denylist should fail closed");
    assertContains(r.stdout + r.stderr, "SCAN_READ_ERROR", "Should report sanitized read error");
    assertNotContains(r.stdout + r.stderr, "/private/denylist.txt", "Should not print absolute path");
    assertNotContains(r.stdout + r.stderr, "Error:", "Should not print stack trace");
    assertNotContains(r.stdout + r.stderr, "ENOENT", "Should not print system error");
} finally { cleanupTempDir(dir); } });
test("source map local path in sources array", () => { const dir = makeTempDir(); try { bsm2(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Source map with local path should exit 1"); assertContains(r.stdout + r.stderr, "SOURCE_MAP_LOCAL_PATH", "Should report SOURCE_MAP_LOCAL_PATH rule"); } finally { cleanupTempDir(dir); } });
test("source map local path in sourceRoot", () => { const dir = makeTempDir(); try { bsr2(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Source map with local sourceRoot should exit 1"); assertContains(r.stdout + r.stderr, "SOURCE_MAP_LOCAL_PATH", "Should report SOURCE_MAP_LOCAL_PATH rule"); } finally { cleanupTempDir(dir); } });
test("denylist terms treated as literals", () => { const dir = makeTempDir(); try { const d = join(dir, "private-denylist.txt"); writeFileSync(d, "test.*pattern"); writeFileSync(join(dir, "secret.txt"), "test_pattern"); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: d }); assert.strictEqual(r.code, 0, "Denylist terms should be treated as literals"); } finally { cleanupTempDir(dir); } });
test("denylist missing file allowed", () => { const dir = makeTempDir(); try { writeFileSync(join(dir, "test.txt"), "normal content"); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: "/nonexistent/path.txt" }); assert.strictEqual(r.code, 0, "Missing denylist file should be allowed"); } finally { cleanupTempDir(dir); } });
test("allowances apply only to matched value - rule definition plus secret", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "a".repeat(24); writeFileSync(join(dir, "scanner.js"), `const RULES = ['PRIVATE_KEY_BLOCK', 'API_TOKEN']; const realSecret = "${s}";`); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should flag real secret even if line has rule definition"); } finally { cleanupTempDir(dir); } });
test("allowances apply only to matched value - redacted plus secret", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "a".repeat(24); writeFileSync(join(dir, "mixed.js"), `const a = "<redacted>"; const b = "${s}";`); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should flag real secret even if line has redacted"); } finally { cleanupTempDir(dir); } });
test("allowances apply only to matched value - example domain plus secret", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "a".repeat(24); writeFileSync(join(dir, "mixed.js"), `const url = "https://example.com"; const key = "${s}";`); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should flag real secret even if line has example domain"); } finally { cleanupTempDir(dir); } });
test("authorization header case insensitive", () => { const dir = makeTempDir(); try { writeFileSync(join(dir, "req.http"), "authorization: bearer token123"); const r = runScanner(["--path", dir]); assertFails(r, 1, "Lowercase authorization should be detected"); assertContains(r.stdout + r.stderr, "AUTHORIZATION_HEADER", "Should report AUTHORIZATION_HEADER"); } finally { cleanupTempDir(dir); } });
test("cookie single pair detected", () => { const dir = makeTempDir(); try { writeFileSync(join(dir, "cookie.txt"), "Cookie: session=abc123"); const r = runScanner(["--path", dir]); assertFails(r, 1, "Single cookie pair should be detected"); assertContains(r.stdout + r.stderr, "COOKIE_HEADER", "Should report COOKIE_HEADER"); } finally { cleanupTempDir(dir); } });
test("output format exact violation lines only", () => { const dir = makeTempDir(); try { brt(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); const lines = r.stdout.trim().split('\n'); for (const line of lines) { assert.ok(/^[A-Z_]+ [^\s:]+:\d+$/.test(line), `Line must match RULE_ID path:line format: ${line}`); } } finally { cleanupTempDir(dir); } });
test("no summary on stdout", () => { const dir = makeTempDir(); try { brt(dir); const r = runScanner(["--path", dir]); assertNotContains(r.stdout, "Found", "Stdout must not contain summary"); assertNotContains(r.stdout, "violation", "Stdout must not contain summary"); assertNotContains(r.stdout, "Scanning", "Stdout must not contain info"); } finally { cleanupTempDir(dir); } });
test("no stack trace in output", () => { const dir = makeTempDir(); try { brt(dir); const r = runScanner(["--path", dir]); assertNotContains(r.stdout + r.stderr, "at ", "Should not contain stack trace"); assertNotContains(r.stdout + r.stderr, "Error:", "Should not contain error trace"); } finally { cleanupTempDir(dir); } });
test("tracked mode verifies test file scanned", () => { const r = runScanner(["--tracked", "--report-scanned-paths"]); assert.strictEqual(r.code, 0, "Report paths should succeed"); const paths = r.stdout.trim().split('\n').filter(p => p); assert.ok(paths.includes("tests/public-safety.test.mjs"), "Must include test file"); assert.ok(paths.includes("docs/public-safety.md"), "Must include docs"); assert.ok(paths.includes(".github/workflows/ci.yml"), "Must include workflow"); assert.ok(paths.includes("package.json"), "Must include root package.json"); });
test("tracked mode verifies docs scanned", () => { const r = runScanner(["--tracked", "--report-scanned-paths"]); assert.strictEqual(r.code, 0, "Report paths should succeed"); const paths = r.stdout.trim().split('\n').filter(p => p); assert.ok(paths.includes("docs/public-safety.md"), "Must include docs"); assert.ok(paths.includes("docs/fixture-policy.md"), "Must include fixture-policy"); });
test("tracked mode verifies workflow scanned", () => { const r = runScanner(["--tracked", "--report-scanned-paths"]); assert.strictEqual(r.code, 0, "Report paths should succeed"); const paths = r.stdout.trim().split('\n').filter(p => p); assert.ok(paths.includes(".github/workflows/ci.yml"), "Must include workflow"); });
test("tracked mode verifies root files scanned", () => { const r = runScanner(["--tracked", "--report-scanned-paths"]); assert.strictEqual(r.code, 0, "Report paths should succeed"); const paths = r.stdout.trim().split('\n').filter(p => p); assert.ok(paths.includes("package.json"), "Must include package.json"); assert.ok(paths.includes("README.md"), "Must include README.md"); });
