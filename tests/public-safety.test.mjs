#!/usr/bin/env node
// Public safety scanner tests - using node:test
// ZERO violation patterns in source - ALL constructed at runtime

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, readFileSync } from "node:fs";
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

function cs(codes) {
    return String.fromCharCode(...codes);
}

// Violation pattern builders - ZERO patterns in source
function pk(d) {
    const s = cs([45,45,45,45,45,66,69,71,73,78,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10,77,73,73,69,118,81,73,66,65,68,65,78,66,103,107,113,104,107,105,71,57,119,48,66,65,81,69,70,65,65,83,67,66,75,99,119,103,103,83,106,65,103,69,65,111,73,66,65,81,68,46,46,46,10,45,45,45,45,45,69,78,68,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45]);
    writeFileSync(join(d, "key.pem"), s);
}

function at(d) {
    const s = cs([115,107,95,108,105,118,101,95]) + "a".repeat(24);
    writeFileSync(join(d, "config.js"), `const apiKey = "${s}";`);
}

function ah(d) {
    writeFileSync(join(d, "request.http"), "Authorization: Bearer " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");
}

function ck(d) {
    const cookie = cs([67,111,111,107,105,101,58,32,115,101,115,115,105,111,110,61,97,98,99,49,50,51,59,32,117,115,101,114,95,105,100,61,52,53,54,59,32,116,111,107,101,110,61,120,121,122,55,56,57]);
    writeFileSync(join(d, "cookies.txt"), cookie);
}

function em(d) {
    writeFileSync(join(d, "contact.md"), "Contact: " + "john.doe" + cs([64]) + "company.com for support.");
}

function ip4(d) {
    writeFileSync(join(d, "server.js"), "const server = '" + "192.168.1.100" + "';");
}

function ip6(d) {
    writeFileSync(join(d, "server.js"), "const server = '" + "2001:db8::1:2:3" + "';");
}

function up(d) {
    const slash = cs([47]);
    const path = slash + ["home", "user", ".config", "app", "data"].join(slash);
    writeFileSync(join(d, "config.json"), `{"dataDir": "${path}"}`);
}

function wp(d) {
    const bs = cs([92]);
    const path = "C:" + bs + ["Users", "user", "AppData", "Local", "App"].join(bs);
    writeFileSync(join(d, "config.json"), `{"dataDir": "${path}"}`);
}

function bp(d) {
    writeFileSync(join(d, "profile.txt"), "Profile: " + cs([47,104,111,109,101,47,117,115,101,114,47,46,99,111,110,102,105,103,47,99,104,114,111,109,101,47,68,101,102,97,117,108,116]));
}

function wh(d) {
    const url = "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X".repeat(24);
    writeFileSync(join(d, "webhook.json"), `{"url": "${url}"}`);
}

function dn(d) {
    writeFileSync(join(d, "private-denylist.txt"), "INTERNAL_PROJECT_X\nSECRET_CODENAME");
    writeFileSync(join(d, "internal.md"), "Project: INTERNAL_PROJECT_X");
}

function ft(d) {
    writeFileSync(join(d, "network.js"), "fet" + "ch('https://api.example.com/data')");
}

function xh(d) {
    writeFileSync(join(d, "xhr.js"), "const xhr = new XMLHtt" + "pRequest();");
}

function ws(d) {
    writeFileSync(join(d, "ws.js"), "const ws = new WebS" + "ocket('wss://api.example.com')");
}

function es(d) {
    writeFileSync(join(d, "sse.js"), "const es = new EventS" + "ource('https://api.example.com/events')");
}

function bb(d) {
    writeFileSync(join(d, "beacon.js"), "navigator.sendBe" + "acon('/analytics', data)");
}

function sm(d) {
    writeFileSync(join(d, "bundle.js.map"), cs([123,34,118,101,114,115,105,111,110,34,58,51,44,34,115,111,117,114,99,101,115,34,58,91,34,47,104,111,109,101,47,117,115,101,114,47,112,114,111,106,101,99,116,47,115,114,99,47,109,97,105,110,46,116,115,34,93,125]));
}

function rt(d) {
    const s = cs([115,107,95,108,105,118,101,95]) + "a".repeat(24);
    writeFileSync(join(d, "root-file.txt"), `secret = "${s}"`);
}

// Negative test builders
function ex(d) {
    writeFileSync(join(d, "contact.md"), "Contact: user@example.com for support.");
}

function r4(d) {
    writeFileSync(join(d, "docs.md"), "Test server: 192.0.2.1");
}

function r6(d) {
    writeFileSync(join(d, "docs.md"), "Test server: 2001:db8::1");
}

function rd(d) {
    writeFileSync(join(d, "config.json"), '{"apiKey": "<redacted>"}');
}

function ns(d) {
    writeFileSync(join(d, "app.js"), 'function hello() { return "world"; }');
}

function pd(d) {
    writeFileSync(join(d, "policy.md"), "## Rules\n- PRIVATE_KEY_BLOCK\n- API_TOKEN\n- AUTHORIZATION_HEADER");
}

function sr(d) {
    writeFileSync(join(d, "scanner.js"), "const RULES = ['PRIVATE_KEY_BLOCK', 'API_TOKEN'];");
}

function sv(d, s) {
    writeFileSync(join(d, "secret.js"), `const secret = "${s}";`);
}

function dl(d) {
    writeFileSync(join(d, "private-denylist.txt"), "INTERNAL_PROJECT_X");
    writeFileSync(join(d, "internal.md"), "Project: INTERNAL_PROJECT_X");
}

function dp(d) {
    writeFileSync(join(d, "private-denylist.txt"), "INTERNAL_PROJECT_X");
    writeFileSync(join(d, "internal.md"), "Project: INTERNAL_PROJECT_X");
}

function sm2(d) {
    writeFileSync(join(d, "bundle.js.map"), cs([123,34,118,101,114,115,105,111,110,34,58,51,44,34,115,111,117,114,99,101,115,34,58,91,34,47,104,111,109,101,47,117,115,101,114,47,112,114,111,106,101,99,116,47,115,114,99,47,109,97,105,110,46,116,115,34,93,125]));
}

function sr2(d) {
    writeFileSync(join(d, "bundle.js.map"), cs([123,34,118,101,114,115,105,111,110,34,58,51,44,34,115,111,117,114,99,101,82,111,111,116,34,58,34,47,104,111,109,101,47,117,115,101,114,47,112,114,111,106,101,99,116,47,34,44,34,115,111,117,114,99,101,115,34,58,91,34,115,114,99,47,109,97,105,110,46,116,115,34,93,125]));
}

function rtf(d) {
    const s = cs([115,107,95,108,105,118,101,95]) + "a".repeat(24);
    writeFileSync(join(d, "root-file.txt"), `secret = "${s}"`);
}

function exm(d) {
    writeFileSync(join(d, "contact.md"), "Contact: user@example.com for support.");
}

function r4v(d) {
    writeFileSync(join(d, "docs.md"), "Test server: 192.0.2.1");
}

function r6v(d) {
    writeFileSync(join(d, "docs.md"), "Test server: 2001:db8::1");
}

function rdd(d) {
    writeFileSync(join(d, "config.json"), '{"apiKey": "<redacted>"}');
}

function nsf(d) {
    writeFileSync(join(d, "app.js"), 'function hello() { return "world"; }');
}

function pex(d) {
    writeFileSync(join(d, "policy.md"), "Allowed domains: example.com, example.org");
}

function ssc(d) {
    writeFileSync(join(d, "scanner.js"), "const RULES = ['PRIVATE_KEY_BLOCK', 'API_TOKEN'];");
}

function sv1(d) {
    const s = cs([115,107,95,108,105,118,101,95]) + "a".repeat(24);
    writeFileSync(join(d, "secret.js"), `const secret = "${s}";`);
}

function sv2(d) {
    const s = cs([115,107,95,108,105,118,101,95]) + "b".repeat(24);
    writeFileSync(join(d, "secret.js"), `const secret = "${s}";`);
}

function dlf(d) {
    writeFileSync(join(d, "private-denylist.txt"), "test.*pattern");
    writeFileSync(join(d, "secret.txt"), "test_pattern");
}

function spf(d) {
    writeFileSync(join(d, "secret.txt"), "test_pattern");
}

function mxv(d) {
    const s = cs([115,107,95,108,105,118,101,95]) + "a".repeat(24);
    writeFileSync(join(d, "mixed.js"), `const a = "<redacted>"; const b = "${s}";`);
}

function pex2(d) {
    writeFileSync(join(d, "policy.md"), "Allowed domains: example.com, example.org");
}

function ssc2(d) {
    writeFileSync(join(d, "scanner.js"), "const RULES = ['PRIVATE_KEY_BLOCK', 'API_TOKEN'];");
}

// ========== POSITIVE TESTS ==========
test("PRIVATE_KEY_BLOCK detected", () => { const dir = makeTempDir(); try { pk(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Private key should exit 1"); assertContains(r.stdout + r.stderr, "PRIVATE_KEY_BLOCK", "Should report PRIVATE_KEY_BLOCK rule"); } finally { cleanupTempDir(dir); } });

test("API_TOKEN detected", () => { const dir = makeTempDir(); try { at(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "API token should exit 1"); assertContains(r.stdout + r.stderr, "API_TOKEN", "Should report API_TOKEN rule"); } finally { cleanupTempDir(dir); } });

test("AUTHORIZATION_HEADER detected", () => { const dir = makeTempDir(); try { ah(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Auth header should exit 1"); assertContains(r.stdout + r.stderr, "AUTHORIZATION_HEADER", "Should report AUTHORIZATION_HEADER rule"); } finally { cleanupTempDir(dir); } });

test("COOKIE_HEADER detected", () => { const dir = makeTempDir(); try { ck(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Cookie header should exit 1"); assertContains(r.stdout + r.stderr, "COOKIE_HEADER", "Should report COOKIE_HEADER rule"); } finally { cleanupTempDir(dir); } });

test("NON_EXAMPLE_EMAIL detected", () => { const dir = makeTempDir(); try { em(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Real email should exit 1"); assertContains(r.stdout + r.stderr, "NON_EXAMPLE_EMAIL", "Should report NON_EXAMPLE_EMAIL rule"); } finally { cleanupTempDir(dir); } });

test("IP_ADDRESS IPv4 detected", () => { const dir = makeTempDir(); try { ip4(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "IPv4 address should exit 1"); assertContains(r.stdout + r.stderr, "IP_ADDRESS", "Should report IP_ADDRESS rule"); } finally { cleanupTempDir(dir); } });

test("IP_ADDRESS IPv6 detected", () => { const dir = makeTempDir(); try { ip6(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "IPv6 address should exit 1"); assertContains(r.stdout + r.stderr, "IP_ADDRESS", "Should report IP_ADDRESS rule"); } finally { cleanupTempDir(dir); } });

test("UNIX_ABSOLUTE_PATH detected", () => { const dir = makeTempDir(); try { up(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Absolute Unix path should exit 1"); assertContains(r.stdout + r.stderr, "UNIX_ABSOLUTE_PATH", "Should report UNIX_ABSOLUTE_PATH rule"); } finally { cleanupTempDir(dir); } });

test("WINDOWS_ABSOLUTE_PATH detected", () => { const dir = makeTempDir(); try { wp(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Windows absolute path should exit 1"); assertContains(r.stdout + r.stderr, "WINDOWS_ABSOLUTE_PATH", "Should report WINDOWS_ABSOLUTE_PATH rule"); } finally { cleanupTempDir(dir); } });

test("BROWSER_PROFILE_PATH detected", () => { const dir = makeTempDir(); try { bp(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Browser profile path should exit 1"); assertContains(r.stdout + r.stderr, "BROWSER_PROFILE_PATH", "Should report BROWSER_PROFILE_PATH rule"); } finally { cleanupTempDir(dir); } });

test("WEBHOOK_URL detected", () => { const dir = makeTempDir(); try { wh(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Webhook URL should exit 1"); assertContains(r.stdout + r.stderr, "WEBHOOK_URL", "Should report WEBHOOK_URL rule"); } finally { cleanupTempDir(dir); } });

test("PRIVATE_DENYLIST_TERM detected", () => { const dir = makeTempDir(); try { dn(dir); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: join(dir, "private-denylist.txt") }); assertFails(r, 1, "Private denylist term should exit 1"); assertNotContains(r.stdout + r.stderr, "INTERNAL_PROJECT_X", "Should not print private denylist term"); } finally { cleanupTempDir(dir); } });

test("RUNTIME_NETWORK_PRIMITIVE fetch detected", () => { const dir = makeTempDir(); try { ft(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Fetch usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });

test("RUNTIME_NETWORK_PRIMITIVE XMLHttpRequest detected", () => { const dir = makeTempDir(); try { xh(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "XMLHttpRequest usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });

test("RUNTIME_NETWORK_PRIMITIVE WebSocket detected", () => { const dir = makeTempDir(); try { ws(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "WebSocket usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });

test("RUNTIME_NETWORK_PRIMITIVE EventSource detected", () => { const dir = makeTempDir(); try { es(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "EventSource usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });

test("RUNTIME_NETWORK_PRIMITIVE sendBeacon detected", () => { const dir = makeTempDir(); try { bb(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "sendBeacon usage should exit 1"); assertContains(r.stdout + r.stderr, "RUNTIME_NETWORK_PRIMITIVE", "Should report RUNTIME_NETWORK_PRIMITIVE rule"); } finally { cleanupTempDir(dir); } });

test("SOURCE_MAP_LOCAL_PATH detected", () => { const dir = makeTempDir(); try { sm(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Source map path should exit 1"); assertContains(r.stdout + r.stderr, "SOURCE_MAP_LOCAL_PATH", "Should report SOURCE_MAP_LOCAL_PATH rule"); } finally { cleanupTempDir(dir); } });

test("root file scan supported", () => { const dir = makeTempDir(); try { rt(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Root file should be scanned"); } finally { cleanupTempDir(dir); } });

// ========== NEGATIVE TESTS ==========
test("example.com email allowed", () => { const dir = makeTempDir(); try { ex(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Example email should be allowed"); } finally { cleanupTempDir(dir); } });

test("reserved IPv4 allowed", () => { const dir = makeTempDir(); try { r4(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Reserved documentation IPv4 should be allowed"); } finally { cleanupTempDir(dir); } });

test("reserved IPv6 allowed", () => { const dir = makeTempDir(); try { r6(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Reserved documentation IPv6 should be allowed"); } finally { cleanupTempDir(dir); } });

test("redacted marker allowed", () => { const dir = makeTempDir(); try { rd(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Redacted marker should be allowed"); } finally { cleanupTempDir(dir); } });

test("normal source allowed", () => { const dir = makeTempDir(); try { ns(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Normal source code should be allowed"); } finally { cleanupTempDir(dir); } });

test("policy document can name rule categories", () => { const dir = makeTempDir(); try { pd(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Policy document naming rules should be allowed"); } finally { cleanupTempDir(dir); } });

test("scanner rule definitions allowed", () => { const dir = makeTempDir(); try { sr(dir); const r = runScanner(["--path", dir]); assert.strictEqual(r.code, 0, "Scanner rule definitions should be allowed"); } finally { cleanupTempDir(dir); } });

test("matched value absent from stdout", () => { const dir = makeTempDir(); try { const s = cs([115,107,95,108,105,118,101,95]) + "a".repeat(24); sv(dir, s); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, s, "Should not print matched secret value in stdout/stderr"); } finally { cleanupTempDir(dir); } });

test("matched value absent from stderr", () => { const dir = makeTempDir(); try { const s = cs([115,107,95,108,105,118,101,95]) + "b".repeat(24); sv(dir, s); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, s, "Should not print matched secret value in stderr"); } finally { cleanupTempDir(dir); } });

test("denylist term absent from output", () => { const dir = makeTempDir(); try { dl(dir); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: join(dir, "private-denylist.txt") }); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, "INTERNAL_PROJECT_X", "Should not print private denylist term"); } finally { cleanupTempDir(dir); } });

test("denylist path absent from output", () => { const dir = makeTempDir(); try { dp(dir); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: join(dir, "private-denylist.txt") }); assertFails(r, 1, "Should exit 1"); assertNotContains(r.stdout + r.stderr, join(dir, "private-denylist.txt"), "Should not print absolute denylist file path"); } finally { cleanupTempDir(dir); } });

// ========== METADATA AND CONTRACT TESTS ==========
test("path file mode scans file not directory", () => { const dir = makeTempDir(); try { const s = cs([115,107,95,108,105,118,101,95]) + "a".repeat(24); writeFileSync(join(dir, "file.txt"), `secret = "${s}";`); const r = runScanner(["--path", join(dir, "file.txt")]); assertFails(r, 1, "Path mode with file should work"); assertContains(r.stdout, "API_TOKEN", "Should report API_TOKEN"); assertContains(r.stdout, "file.txt:", "Should report file path"); assertNotContains(r.stdout + r.stderr, s, "Should not print secret"); } finally { cleanupTempDir(dir); } });

test("path directory mode scans directory", () => { const dir = makeTempDir(); try { rt(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Path mode with directory should work"); } finally { cleanupTempDir(dir); } });

test("read errors fail closed with sanitized error", () => { const dir = makeTempDir(); try {
    const d = join(dir, "private-denylist.txt");
    mkdirSync(d);
    writeFileSync(join(dir, "test.txt"), "normal content");
    const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: d });
    assertFails(r, 1, "Unreadable denylist should fail closed");
    assertContains(r.stdout + r.stderr, "SCAN_READ_ERROR", "Should report sanitized read error");
    assertNotContains(r.stdout + r.stderr, "/private" + "/denylist.txt", "Should not print absolute path");
    assertNotContains(r.stdout + r.stderr, "Error:", "Should not print stack trace");
    assertNotContains(r.stdout + r.stderr, "ENOENT", "Should not print system error");
} finally { cleanupTempDir(dir); } });

test("source map local path in sources array", () => { const dir = makeTempDir(); try { sm2(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Source map with local path should exit 1"); assertContains(r.stdout + r.stderr, "SOURCE_MAP_LOCAL_PATH", "Should report SOURCE_MAP_LOCAL_PATH rule"); } finally { cleanupTempDir(dir); } });

test("source map local path in sourceRoot", () => { const dir = makeTempDir(); try { sr2(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Source map with local sourceRoot should exit 1"); assertContains(r.stdout + r.stderr, "SOURCE_MAP_LOCAL_PATH", "Should report SOURCE_MAP_LOCAL_PATH rule"); } finally { cleanupTempDir(dir); } });

test("denylist terms treated as literals", () => { const dir = makeTempDir(); try { const d = join(dir, "private-denylist.txt"); writeFileSync(d, "test.*pattern"); writeFileSync(join(dir, "secret.txt"), "test_pattern"); const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: d }); assert.strictEqual(r.code, 0, "Denylist terms should be treated as literals"); } finally { cleanupTempDir(dir); } });

test("denylist missing file allowed", () => { const dir = makeTempDir(); try { writeFileSync(join(dir, "test.txt"), "normal content"); const slash = cs([47]); const missingPath = slash + "nonexistent" + slash + "path.txt"; const r = runScanner(["--path", dir], { COPYMARKER_PRIVATE_DENYLIST_FILE: missingPath }); assert.strictEqual(r.code, 0, "Missing denylist file should be allowed"); } finally { cleanupTempDir(dir); } });

test("allowances apply only to matched value - rule definition plus secret", () => { const dir = makeTempDir(); try { const s = cs([115,107,95,108,105,118,101,95]) + "a".repeat(24); writeFileSync(join(dir, "scanner.js"), `const RULES = ['PRIVATE_KEY_BLOCK', 'API_TOKEN']; const realSecret = "${s}";`); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should flag real secret even if line has rule definition"); } finally { cleanupTempDir(dir); } });

test("allowances apply only to matched value - redacted plus secret", () => { const dir = makeTempDir(); try { const s = cs([115,107,95,108,105,118,101,95]) + "a".repeat(24); writeFileSync(join(dir, "mixed.js"), `const a = "<redacted>"; const b = "${s}";`); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should flag real secret even if line has redacted"); } finally { cleanupTempDir(dir); } });

test("allowances apply only to matched value - example domain plus secret", () => { const dir = makeTempDir(); try { const s = cs([115,107,95,108,105,118,101,95]) + "a".repeat(24); writeFileSync(join(dir, "mixed.js"), `const url = "https://example.com"; const key = "${s}";`); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should flag real secret even if line has example domain"); } finally { cleanupTempDir(dir); } });

test("authorization header case insensitive", () => { const dir = makeTempDir(); try {
    const headerName = ["author", "ization"].join("");
    const scheme = ["bear", "er"].join("");
    writeFileSync(join(dir, "req.http"), headerName + ": " + scheme + " token123");
    const r = runScanner(["--path", dir]);
    assertFails(r, 1, "Lowercase authorization should be detected");
    assertContains(r.stdout + r.stderr, "AUTHORIZATION_HEADER", "Should report AUTHORIZATION_HEADER");
} finally { cleanupTempDir(dir); } });

test("cookie single pair detected", () => { const dir = makeTempDir(); try { const cookie = cs([67,111,111,107,105,101,58,32,115,101,115,115,105,111,110,61,97,98,99,49,50,51]); writeFileSync(join(dir, "cookie.txt"), cookie); const r = runScanner(["--path", dir]); assertFails(r, 1, "Single cookie pair should be detected"); assertContains(r.stdout + r.stderr, "COOKIE_HEADER", "Should report COOKIE_HEADER"); } finally { cleanupTempDir(dir); } });

test("output format exact violation lines only", () => { const dir = makeTempDir(); try { rt(dir); const r = runScanner(["--path", dir]); assertFails(r, 1, "Should exit 1"); const lines = r.stdout.trim().split('\n'); for (const line of lines) { assert.ok(/^[A-Z_]+ [^\s:]+:\d+$/.test(line), `Line must match RULE_ID path:line format: ${line}`); } } finally { cleanupTempDir(dir); } });

test("no summary on stdout", () => { const dir = makeTempDir(); try { rt(dir); const r = runScanner(["--path", dir]); assertNotContains(r.stdout, "Found", "Stdout must not contain summary"); assertNotContains(r.stdout, "violation", "Stdout must not contain summary"); assertNotContains(r.stdout, "Scanning", "Stdout must not contain info"); } finally { cleanupTempDir(dir); } });

test("no stack trace in output", () => { const dir = makeTempDir(); try { rt(dir); const r = runScanner(["--path", dir]); assertNotContains(r.stdout + r.stderr, "at ", "Should not contain stack trace"); assertNotContains(r.stdout + r.stderr, "Error:", "Should not contain error trace"); } finally { cleanupTempDir(dir); } });

test("tracked mode verifies test file scanned", () => { const r = runScanner(["--tracked", "--report-scanned-paths"]); assert.strictEqual(r.code, 0, "Report paths should succeed"); const paths = r.stdout.trim().split('\n').filter(p => p); assert.ok(paths.includes("tests/public-safety.test.mjs"), "Must include test file"); assert.ok(paths.includes("docs/public-safety.md"), "Must include docs"); assert.ok(paths.includes(".github/workflows/ci.yml"), "Must include workflow"); assert.ok(paths.includes("package.json"), "Must include root package.json"); });

test("tracked mode verifies docs scanned", () => { const r = runScanner(["--tracked", "--report-scanned-paths"]); assert.strictEqual(r.code, 0, "Report paths should succeed"); const paths = r.stdout.trim().split('\n').filter(p => p); assert.ok(paths.includes("docs/public-safety.md"), "Must include docs"); assert.ok(paths.includes("docs/fixture-policy.md"), "Must include fixture-policy"); });

test("tracked mode verifies workflow scanned", () => { const r = runScanner(["--tracked", "--report-scanned-paths"]); assert.strictEqual(r.code, 0, "Report paths should succeed"); const paths = r.stdout.trim().split('\n').filter(p => p); assert.ok(paths.includes(".github/workflows/ci.yml"), "Must include workflow"); });

test("tracked mode verifies root files scanned", () => { const r = runScanner(["--tracked", "--report-scanned-paths"]); assert.strictEqual(r.code, 0, "Report paths should succeed"); const paths = r.stdout.trim().split('\n').filter(p => p); assert.ok(paths.includes("package.json"), "Must include package.json"); assert.ok(paths.includes("README.md"), "Must include README.md"); });
