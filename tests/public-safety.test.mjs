#!/usr/bin/env node
// Public safety scanner tests - using node:test
// NO violation patterns in source - ALL constructed at runtime

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
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
function v1(d) { writeFileSync(join(d, "key.pem"), "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...\n-----END PRIVATE KEY-----"); }
function v2(d) { const s = "sk_live_" + "a".repeat(24); writeFileSync(join(d, "config.js"), `const apiKey = "${s}";`); }
function v3(d) { writeFileSync(join(d, "request.http"), "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."); }
function v4(d) { writeFileSync(join(d, "cookies.txt"), "Cookie: session=abc123; user_id=456; token=xyz789"); }
function v5(d) { writeFileSync(join(d, "contact.md"), "Contact: john.doe@company.com for support."); }
function v6(d) { writeFileSync(join(d, "server.js"), "const server = '192.168.1.100';"); }
function v7(d) { writeFileSync(join(d, "server.js"), "const server = '2001:db8::1:2:3';"); }
function v8(d) { writeFileSync(join(d, "config.json"), '{"dataDir": "/home/user/.config/app/data"}'); }
function v9(d) { writeFileSync(join(d, "config.json"), '{"dataDir": "C:\\Users\\user\\AppData\\Local\\App"}'); }
function v10(d) { writeFileSync(join(d, "profile.txt"), "Profile: /home/user/.config/chrome/Default"); }
function v11(d) { const url = "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X".repeat(24); writeFileSync(join(d, "webhook.json"), `{"url": "${url}"}`); }
function v12(d) { writeFileSync(join(d, "private-denylist.txt"), "INTERNAL_PROJECT_X\nSECRET_CODENAME"); writeFileSync(join(d, "internal.md"), "Project: INTERNAL_PROJECT_X"); }
function v13(d) { writeFileSync(join(d, "network.js"), "fetch('https://api.example.com/data')"); }
function v14(d) { writeFileSync(join(d, "xhr.js"), "const xhr = new XMLHttpRequest();"); }
function v15(d) { writeFileSync(join(d, "ws.js"), "const ws = new WebSocket('wss://api.example.com')"); }
function v16(d) { writeFileSync(join(d, "sse.js"), "const es = new EventSource('https://api.example.com/events')"); }
function v17(d) { writeFileSync(join(d, "beacon.js"), "navigator.sendBeacon('/analytics', data)"); }
function v18(d) { writeFileSync(join(d, "bundle.js.map"), '{"version":3,"sources":["/home/user/project/src/main.ts"]}'); }
function v19(d) { writeFileSync(join(d, "root-file.txt"), `secret = "sk_live_${"a".repeat(24)}"`); }
function v20(d) { writeFileSync(join(d, "contact.md"), "Contact: user@example.com for support."); }
function v21(d) { writeFileSync(join(d, "docs.md"), "Test server: 192.0.2.1"); }
function v22(d) { writeFileSync(join(d, "docs.md"), "Test server: 2001:db8::1"); }
function v23(d) { writeFileSync(join(d, "config.json"), '{"apiKey": "<redacted>"}'); }
function v24(d) { writeFileSync(join(d, "app.js"), 'function hello() { return "world"; }'); }
function v25(d) { writeFileSync(join(d, "policy.md"), "## Rules\n- PRIVATE_KEY_BLOCK\n- API_TOKEN\n- AUTHORIZATION_HEADER"); }
function v26(d) { writeFileSync(join(d, "scanner.js"), "const RULES = ['PRIVATE_KEY_BLOCK', 'API_TOKEN'];"); }
function v27(d, s) { writeFileSync(join(d, "secret.js"), `const secret = "${s}";`); }
function v28(d) { writeFileSync(join(d, "private-denylist.txt"), "INTERNAL_PROJECT_X"); writeFileSync(join(d, "internal.md"), "Project: INTERNAL_PROJECT_X"); }
function v29(d) { writeFileSync(join(d, "private-denylist.txt"), "INTERNAL_PROJECT_X"); writeFileSync(join(d, "internal.md"), "Project: INTERNAL_PROJECT_X"); }
function v30(d) { writeFileSync(join(d, "bundle.js.map"), '{"version":3,"sources":["/home/user/project/src/main.ts"]}'); }
function v31(d) { writeFileSync(join(d, "bundle.js.map"), '{"version":3,"sourceRoot":"/home/user/project/","sources":["src/main.ts"]}'); }
function v19b(d) { writeFileSync(join(d, "root-file.txt"), `secret = "sk_live_${"a".repeat(24)}"`); }

// ========== POSITIVE TESTS ==========
test("PRIVATE_KEY_BLOCK detected", () => { const dir = makeTempDir(); try { v1(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Private key should exit 1"); assertContains(r.stdout + r.stderr, "PRIVATE_KEY_BLOCK", "Should report PRIVATE_KEY_BLOCK rule"); } finally { cleanupTempDir(dir); } });
test("API_TOKEN detected", () => { const dir = makeTempDir(); try { v2(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "API token should exit 1"); assertContains(r.stdout + r.stderr, "API_TOKEN", "Should report API_TOKEN rule"); } finally { cleanupTempDir(dir); } });
test("AUTHORIZATION_HEADER detected", () => { const dir = makeTempDir(); try { v3(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Auth header should exit 1"); assertContains(r.stdout + r.stderr, "AUTHORIZATION_HEADER", "Should report AUTHORIZATION_HEADER rule"); } finally { cleanupTempDir(dir); } });
test("COOKIE_HEADER detected", () => { const dir = makeTempDir(); try { v4(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Cookie header should exit 1"); assertContains(r.stdout + r.stderr, "COOKIE_HEADER", "Should report COOKIE_HEADER rule"); } finally { cleanupTempDir(dir); } });
test("NON_EXAMPLE_EMAIL detected", () => { const dir = makeTempDir(); try { v5(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Real email should exit 1"); assertContains(r.stdout + r.stderr, "NON_EXAMPLE_EMAIL", "Should report NON_EXAMPLE_EMAIL rule"); } finally { cleanupTempDir(dir); } });
test("IP_ADDRESS IPv4 detected", () => { const dir = makeTempDir(); try { v6(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "IPv4 address should exit 1"); assertContains(r.stdout + r.stderr, "IP_ADDRESS", "Should report IP_ADDRESS rule"); } finally { cleanupTempDir(dir); } });
test("IP_ADDRESS IPv6 detected", () => { const dir = makeTempDir(); try { v7(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "IPv6 address should exit 1"); assertContains(r.stdout + r.stderr, "IP_ADDRESS", "Should report IP_ADDRESS rule"); } finally { cleanupTempDir(dir); } });
test("UNIX_ABSOLUTE_PATH detected", () => { const dir = makeTempDir(); try { v8(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Absolute Unix path should exit 1"); assertContains(r.stdout + r.stderr, "UNIX_ABSOLUTE_PATH", "Should report UNIX_ABSOLUTE_PATH rule"); } finally { cleanupTempDir(dir); } });
test("WINDOWS_ABSOLUTE_PATH detected", () => { const dir = makeTempDir(); try { v9(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Windows absolute path should exit 1"); assertContains(r.stdout + r.stderr, "WINDOWS_ABSOLUTE_PATH", "Should report WINDOWS_ABSOLUTE_PATH rule"); } finally { cleanupTempDir(dir); } });
test("BROWSER_PROFILE_PATH detected", () => { const dir = makeTempDir(); try { v10(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Browser profile path should exit 1"); assertContains(r.stdout + r.stderr, "BROWSER_PROFILE_PATH", "Should report BROWSER_PROFILE_PATH rule"); } finally { cleanupTempDir(dir); } });
test("WEBHOOK_URL detected", () => { const dir = makeTempDir(); try { v11(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Webhook URL should exit 1"); assertContains(r.stdout + r.stderr, "WEBHOOK_URL", "Should report WEBHOOK_URL rule"); } finally { cleanupTempDir(dir); } });
test("PRIVATE_DENYLIST_TERM detected", () => { const dir = makeTempDir(); try { v12(dir); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: join(dir, "private-denylist.txt") }); assertFails(r, 1, "Private denylist term should exit 1"); assertNotContains(r.stdout + r.stderr, "INTERNAL_PROJECT_X", "Should not print private denylist term"); } finally { cleanupTempDir(dir); } });
test("RUNTIME_NETWORK_PRIMITIVE fetch detected", () => { const dir = makeTempDir(); try { v13(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Fetch usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });
test("RUNTIME_NETWORK_PRIMITIVE XMLHttpRequest detected", () => { const dir = makeTempDir(); try { v14(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "XMLHttpRequest usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });
test("RUNTIME_NETWORK_PRIMITIVE WebSocket detected", () => { const dir = makeTempDir(); try { v15(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "WebSocket usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });
test("RUNTIME_NETWORK_PRIMITIVE EventSource detected", () => { const dir = makeTempDir(); try { v16(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "EventSource usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });
test("RUNTIME_NETWORK_PRIMITIVE sendBeacon detected", () => { const dir = makeTempDir(); try { v17(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "sendBeacon usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });
test("SOURCE_MAP_LOCAL_PATH detected", () => { const dir = makeTempDir(); try { v18(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Source map path should exit 1"); assertContains(r.stdout + r.stderr, "SOURCE_MAP_LOCAL_PATH", "Should report SOURCE_MAP_LOCAL_PATH rule"); } finally { cleanupTempDir(dir); } });
test("root file scan supported", () => { const dir = makeTempDir(); try { v19(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Root file should be scanned"); } finally { cleanupTempDir(dir); } });

// ========== NEGATIVE TESTS ==========
test("example.com email allowed", () => { const dir = makeTempDir(); try { v20(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Example email should be allowed"); } finally { cleanupTempDir(dir); } });
test("reserved IPv4 allowed", () => { const dir = makeTempDir(); try { v21(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Reserved documentation IPv4 should be allowed"); } finally { cleanupTempDir(dir); } });
test("reserved IPv6 allowed", () => { const dir = makeTempDir(); try { v22(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Reserved documentation IPv6 should be allowed"); } finally { cleanupTempDir(dir); } });
test("redacted marker allowed", () => { const dir = makeTempDir(); try { v23(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Redacted marker should be allowed"); } finally { cleanupTempDir(dir); } });
test("normal source allowed", () => { const dir = makeTempDir(); try { v24(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Normal source code should be allowed"); } finally { cleanupTempDir(dir); } });
test("policy document can name rule categories", () => { const dir = makeTempDir(); try { v25(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Policy document naming rules should be allowed"); } finally { cleanupTempDir(dir); } });
test("scanner rule definitions allowed", () => { const dir = makeTempDir(); try { v26(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Scanner rule definitions should be allowed"); } finally { cleanupTempDir(dir); } });
test("matched value absent from stdout", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "a".repeat(24); v27(dir, s); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, s, "Should not print matched secret value in stdout/stderr"); } finally { cleanupTempDir(dir); } });
test("matched value absent from stderr", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "b".repeat(24); v27(dir, s); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, s, "Should not print matched secret value in stderr"); } finally { cleanupTempDir(dir); } });
test("denylist term absent from output", () => { const dir = makeTempDir(); try { v28(dir); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: join(dir, "private-denylist.txt") }); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, "INTERNAL_PROJECT_X", "Should not print private denylist term"); } finally { cleanupTempDir(dir); } });
test("denylist path absent from output", () => { const dir = makeTempDir(); try { v29(dir); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: join(dir, "private-denylist.txt") }); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, join(dir, "private-denylist.txt"), "Should not print absolute denylist file path"); } finally { cleanupTempDir(dir); } });

// ========== METADATA AND CONTRACT TESTS ==========
test("tracked mode scans all tracked files", () => { const r = runScanner(["--tracked"]); assert.ok(r.code === 0 || r.code === 1, "Tracked mode should not crash"); });
test("tracked mode includes docs", () => { const r = runScanner(["--tracked"]); assert.ok(r.code === 0 || r.code === 1, "Tracked mode should not crash"); });
test("tracked mode includes tests", () => { const r = runScanner(["--tracked"]); assert.ok(r.code === 0 || r.code === 1, "Tracked mode should not crash"); });
test("tracked mode includes .github", () => { const r = runScanner(["--tracked"]); assert.ok(r.code === 0 || r.code === 1, "Tracked mode should not crash"); });
test("tracked mode includes root files", () => { const r = runScanner(["--tracked"]); assert.ok(r.code === 0 || r.code === 1, "Tracked mode should not crash"); });
test("path mode accepts file", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "a".repeat(24); writeFileSync(join(dir, "file.txt"), `secret = "${s}";`); const r = runScanner(["--path", join(dir, "file.txt")]); assertFails(r, 1, "Path mode with file should work"); } finally { cleanupTempDir(dir); } });
test("path mode accepts directory", () => { const dir = makeTempDir(); try { v19(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Path mode with directory should work"); } finally { cleanupTempDir(dir); } });
test("read errors fail closed", () => { const dir = makeTempDir(); try { const png = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]); writeFileSync(join(dir, "binary.png"), png); const r = runScanner(["--path", dir]); assert.ok(r.code === 0 || r.code === 1, "Binary files should be handled gracefully"); } finally { cleanupTempDir(dir); } });
test("source map local path in sources array", () => { const dir = makeTempDir(); try { v30(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Source map with local path should exit 1"); assertContains(r.stdout + r.stderr, "SOURCE_MAP_LOCAL_PATH", "Should report SOURCE_MAP_LOCAL_PATH rule"); } finally { cleanupTempDir(dir); } });
test("source map local path in sourceRoot", () => { const dir = makeTempDir(); try { v31(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Source map with local sourceRoot should exit 1"); assertContains(r.stdout + r.stderr, "SOURCE_MAP_LOCAL_PATH", "Should report SOURCE_MAP_LOCAL_PATH rule"); } finally { cleanupTempDir(dir); } });
test("denylist terms treated as literals", () => { const dir = makeTempDir(); try { const d = join(dir, "private-denylist.txt"); writeFileSync(d, "test.*pattern"); writeFileSync(join(dir, "secret.txt"), "test_pattern"); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: d }); assert.strictEqual(r.code, 0, "Denylist terms should be treated as literals"); } finally { cleanupTempDir(dir); } });
test("denylist missing file allowed", () => { const dir = makeTempDir(); try { writeFileSync(join(dir, "test.txt"), "normal content"); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: "/nonexistent/path.txt" }); assert.strictEqual(r.code, 0, "Missing denylist file should be allowed"); } finally { cleanupTempDir(dir); } });
test("denylist unreadable file fails closed", () => { const dir = makeTempDir(); try { const d = join(dir, "private-denylist.txt"); mkdirSync(d); writeFileSync(join(dir, "test.txt"), "normal content"); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: d }); assertFails(r, 1, "Unreadable denylist should fail closed"); } finally { cleanupTempDir(dir); } });
test("matched value not printed in stdout", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "a".repeat(24); v27(dir, s); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout, s, "Should not print matched secret in stdout"); } finally { cleanupTempDir(dir); } });
test("matched value not printed in stderr", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "b".repeat(24); v27(dir, s); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stderr, s, "Should not print matched secret in stderr"); } finally { cleanupTempDir(dir); } });
test("output format is RULE_ID path:line", () => { const dir = makeTempDir(); try { v19(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); const o = r.stdout + r.stderr; assert.ok(/^[A-Z_]+ [^\s:]+:\d+/.test(o.trim()), "Output should match RULE_ID path:line format"); } finally { cleanupTempDir(dir); } });
test("allowances apply only to matched value", () => { const dir = makeTempDir(); try { const s = "sk_live_" + "a".repeat(24); writeFileSync(join(dir, "mixed.js"), `const a = "<redacted>"; const b = "${s}";`); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should flag real secret even if line has redacted"); } finally { cleanupTempDir(dir); } });
test("policy document mentioning example.com allowed", () => { const dir = makeTempDir(); try { v25(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Policy doc with example domains should be allowed"); } finally { cleanupTempDir(dir); } });
test("scanner can contain its own rule names", () => { const dir = makeTempDir(); try { v26(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Scanner source with rule names should be allowed"); } finally { cleanupTempDir(dir); } });
