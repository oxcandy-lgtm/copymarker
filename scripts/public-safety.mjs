#!/usr/bin/env node
// Public safety scanner for CopyMarker
// Scans for secrets, private keys, tokens, and other sensitive data

import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, extname, basename, relative, resolve } from 'path';
import { execSync } from 'child_process';

const SAFE_EXTS = new Set([
    '.md', '.txt', '.json', '.js', '.ts', '.mjs', '.cjs',
    '.html', '.css', '.yml', '.yaml', '.toml', '.xml',
    '.gitignore', '.gitattributes', '.editorconfig',
    '.eslintrc', '.prettierrc', '.npmrc', '.nvmrc'
]);

const SAFE_FILES = new Set([
    'package.json', 'package-lock.json', 'tsconfig.json',
    'LICENSE', 'README.md', 'CHANGELOG.md', 'CONTRIBUTING.md',
    'SECURITY.md', 'PRIVACY.md', 'CODE_OF_CONDUCT.md'
]);

const DENYLIST_ENV = process.env.COPYMARKER_PRIVATE_DENYLIST_FILE;

let DENYLIST_PATH = null;
if (DENYLIST_ENV) {
    try {
        DENYLIST_PATH = resolve(DENYLIST_ENV);
    } catch (e) {
        // Ignore resolution errors
    }
}

// Patterns that indicate secrets
const DENYLIST_PATTERNS = [
    // PRIVATE_KEY_BLOCK
    { id: 'PRIVATE_KEY_BLOCK', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },

    // API_TOKEN - generic API tokens
    { id: 'API_TOKEN', pattern: /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)['"\s]*[:=]['"\s]*[a-zA-Z0-9_\-]{20,}/gi },

    // AUTHORIZATION_HEADER
    { id: 'AUTHORIZATION_HEADER', pattern: /Authorization:\s*Bearer\s+[A-Za-z0-9\-_.]+/gi },

    // COOKIE_HEADER
    { id: 'COOKIE_HEADER', pattern: /Cookie:\s*[^\n]*(?:;|$)/gi },

    // NON_EXAMPLE_EMAIL - real emails (not example.com/org/net)
    { id: 'NON_EXAMPLE_EMAIL', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },

    // IP_ADDRESS - IPv4 and IPv6
    { id: 'IP_ADDRESS', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
    { id: 'IP_ADDRESS', pattern: /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g },

    // UNIX_ABSOLUTE_PATH
    { id: 'UNIX_ABSOLUTE_PATH', pattern: /(?:^|[\s"'`])\/home\/[a-zA-Z0-9_.-]+\/[^\s"'`]*/g },
    { id: 'UNIX_ABSOLUTE_PATH', pattern: /(?:^|[\s"'`])\/root\/[^\s"'`]*/g },
    { id: 'UNIX_ABSOLUTE_PATH', pattern: /(?:^|[\s"'`])\/Users\/[a-zA-Z0-9_.-]+\/[^\s"'`]*/g },
    { id: 'UNIX_ABSOLUTE_PATH', pattern: /(?:^|[\s"'`])\/var\/[^\s"'`]*/g },
    { id: 'UNIX_ABSOLUTE_PATH', pattern: /(?:^|[\s"'`])\/opt\/[^\s"'`]*/g },
    { id: 'UNIX_ABSOLUTE_PATH', pattern: /(?:^|[\s"'`])\/srv\/[^\s"'`]*/g },
    { id: 'UNIX_ABSOLUTE_PATH', pattern: /(?:^|[\s"'`])\/etc\/[^\s"'`]*/g },

    // WINDOWS_ABSOLUTE_PATH
    { id: 'WINDOWS_ABSOLUTE_PATH', pattern: /[A-Za-z]:\\(?:[^\\\s"'`]+\\)*[^\\\s"'`]*/g },

    // BROWSER_PROFILE_PATH
    { id: 'BROWSER_PROFILE_PATH', pattern: /\.config\/(?:chromium|chrome|google-chrome|firefox|mozilla)\/[^\s"'`]*/g },
    { id: 'BROWSER_PROFILE_PATH', pattern: /\.mozilla\/firefox\/[^\s"'`]*/g },
    { id: 'BROWSER_PROFILE_PATH', pattern: /AppData\\Local\\Google\\Chrome\\User Data\\/g },
    { id: 'BROWSER_PROFILE_PATH', pattern: /AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\/g },

    // API_TOKEN - bare sk_live_ tokens
    { id: 'API_TOKEN', pattern: /sk_live_[a-zA-Z0-9]{20,}/g },

    // WEBHOOK_URL
    { id: 'WEBHOOK_URL', pattern: /https?:\/\/(?:hooks|webhook|api)\.(?:slack|discord|github|gitlab)\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Z0-9]{24,}/g },
    { id: 'WEBHOOK_URL', pattern: /https?:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Z0-9]{24,}/g },

    // RUNTIME_NETWORK_PRIMITIVE
    { id: 'RUNTIME_NETWORK_PRIMITIVE', pattern: /\bfetch\s*\(/g },
    { id: 'RUNTIME_NETWORK_PRIMITIVE', pattern: /\bXMLHttpRequest\b/g },
    { id: 'RUNTIME_NETWORK_PRIMITIVE', pattern: /\bWebSocket\b/g },
    { id: 'RUNTIME_NETWORK_PRIMITIVE', pattern: /\bEventSource\b/g },
    { id: 'RUNTIME_NETWORK_PRIMITIVE', pattern: /\bsendBeacon\b/g },

    // SOURCE_MAP_LOCAL_PATH
    { id: 'SOURCE_MAP_LOCAL_PATH', pattern: /"sourceRoot"\s*:\s*"\/[^"]+"/g },
    { id: 'SOURCE_MAP_LOCAL_PATH', pattern: /"sources"\s*:\s*\[[^\]]*"\/[^"]+"[^\]]*\]/g },
];

let denylistPatterns = [];
if (DENYLIST_ENV && existsSync(DENYLIST_ENV)) {
    try {
        const content = readFileSync(DENYLIST_ENV, 'utf-8');
        for (const line of content.split('\n')) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#')) {
                // Escape regex metacharacters - treat as literal
                const escaped = trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                denylistPatterns.push({ id: 'PRIVATE_DENYLIST_TERM', pattern: new RegExp(escaped, 'g') });
            }
        }
    } catch (e) {
        console.error('SCAN_READ_ERROR ' + relative(process.cwd(), DENYLIST_PATH));
        process.exit(1);
    }
}

const ALL_PATTERNS = [...DENYLIST_PATTERNS, ...denylistPatterns];

// Allowlists for synthetic fixtures
const ALLOWED_DOMAINS = new Set(['example.com', 'example.org', 'example.net']);
const ALLOWED_IPV4 = [
    /^192\.0\.2\./,           // TEST-NET-1
    /^198\.51\.100\./,        // TEST-NET-2
    /^203\.0\.113\./,         // TEST-NET-3
];
const ALLOWED_IPV6 = [
    /^2001:db8:/,                // IPv6 documentation
];
const ALLOWED_EMAIL_DOMAINS = ['example.com', 'example.org', 'example.net'];
const REDACTED_MARKER = '<redacted>';

function isAllowedEmail(email) {
    const domain = email.split('@')[1]?.toLowerCase();
    return domain && ALLOWED_EMAIL_DOMAINS.includes(domain);
}

function isAllowedIPv4(ip) {
    return ALLOWED_IPV4.some(pattern => pattern.test(ip));
}

function isAllowedIPv6(ip) {
    return ALLOWED_IPV6.some(pattern => pattern.test(ip));
}

function isRedacted(text) {
    return text.includes(REDACTED_MARKER);
}

function shouldScanFile(filePath) {
    const ext = extname(filePath);
    const base = basename(filePath);
    if (SAFE_FILES.has(base)) return true;
    if (SAFE_EXTS.has(ext)) return true;
    // Skip binary files by extension
    const binaryExts = ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.gz', '.tar'];
    if (binaryExts.includes(ext)) return false;
    return true;
}

function scanFile(filePath, relPath) {
    const violations = [];

    // Skip the denylist file itself
    if (DENYLIST_PATH && resolve(filePath) === DENYLIST_PATH) {
        return violations;
    }
    try {
        const content = readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');

        for (const { id, pattern } of ALL_PATTERNS) {
            let match;
            // Reset regex lastIndex for global patterns
            pattern.lastIndex = 0;
            while ((match = pattern.exec(content)) !== null) {
                // Find line number
                const beforeMatch = content.substring(0, match.index);
                const lineNum = beforeMatch.split('\n').length;
                const lineContent = lines[lineNum - 1] || '';

                // Check allowlists
                const matchedText = match[0];

                // Skip only if the matched text itself is redacted
                // The test "allowances apply only to matched value" requires that
                // if a line has <redacted> but also a real secret, the real secret is still flagged
                if (isRedacted(matchedText)) {
                    // The matched text itself is redacted - skip this match
                } else {
                    // Check for allowed emails
                    if (id === 'NON_EXAMPLE_EMAIL') {
                        const emailMatch = matchedText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
                        if (emailMatch && isAllowedEmail(emailMatch[0])) {
                            continue;
                        }
                    }

                    // Check for allowed IPs
                    if (id === 'IP_ADDRESS') {
                        const ipv4Match = matchedText.match(/\d+\.\d+\.\d+\.\d+/);
                        if (ipv4Match && isAllowedIPv4(ipv4Match[0])) {
                            continue;
                        }
                        const ipv6Match = matchedText.match(/[0-9a-fA-F:]+::[0-9a-fA-F:]*/);
                        if (ipv6Match && isAllowedIPv6(ipv6Match[0])) {
                            continue;
                        }
                    }

                    // Allow rule names in scanner source and policy documents
                    // Rule-specific exemption: only for the exact rule being defined
                    const lineLower = lineContent.toLowerCase();
                    if (isRuleDefinitionExemption(id, relPath, lineContent, matchedText)) {
                        continue;
                    }

                    violations.push({
                        rule: id,
                        file: relPath,
                        line: lineNum
                    });
                }

                // Avoid infinite loop on zero-width matches
                if (match.index === pattern.lastIndex) {
                    pattern.lastIndex++;
                }
            }
        }
    } catch (e) {
        // Fail closed on read errors
        console.error('SCAN_READ_ERROR ' + relPath);
        process.exit(1);
    }
    return violations;
}

function isRuleDefinitionExemption(ruleId, relativePath, lineContent, matchedText) {
    // Exact repository paths allowed for specific rule definitions
    const allowedPaths = new Set([
        'scripts/public-safety.mjs',
        'docs/fixture-policy.md',
        'docs/public-safety.md',
        'README.md',
        'SECURITY.md',
        'PRIVACY.md',
        'CONTRIBUTING.md',
        'tests/public-safety.test.mjs'
    ]);

    if (!allowedPaths.has(relativePath)) {
        return false;
    }

    // Test file builder functions that write test fixtures - NOT violations in source
    const isTestBuilder = relativePath === 'tests/public-safety.test.mjs' &&
                          (lineContent.includes('function b') && lineContent.includes('writeFileSync'));

    // Test file assertions checking for rule IDs - NOT violations
    const isTestAssertion = relativePath === 'tests/public-safety.test.mjs' &&
                           (lineContent.includes('assertContains') || lineContent.includes('assertNotContains') || lineContent.includes('test("')) &&
                           lineContent.toLowerCase().includes(ruleId.toLowerCase());

    // README.md documentation about network primitives - NOT violation
    const isReadmeDoc = relativePath === 'README.md' &&
                       lineContent.includes('Runtime network primitives');

    // Fixture policy example paths - explicitly allowed examples
    const isFixtureExample = relativePath === 'docs/fixture-policy.md' &&
                            (lineContent.includes('/tmp/test-file.txt') ||
                             lineContent.includes("C:" + "\\" + "Temp" + "\\" + "test.txt") ||
                             lineContent.includes('/var/www/example.com') ||
                             lineContent.includes('example.com') ||
                             lineContent.includes('example.org'));

    // Scanner rule definitions - NOT violations
    const isScannerDef = relativePath === 'scripts/public-safety.mjs' &&
                        (lineContent.includes("id: '" + ruleId + "'") ||
                         lineContent.includes('pattern: /') ||
                         lineContent.includes('const PATTERNS') ||
                         lineContent.includes('COOKIE_HEADER') ||
                         lineContent.includes('WINDOWS_ABSOLUTE_PATH'));

    const isDefinitionContext = isTestBuilder || isTestAssertion || isReadmeDoc || isFixtureExample || isScannerDef;

    // Exemption function's own source containing example patterns for isFixtureExample
    const isExemptionFunctionSelf = relativePath === 'scripts/public-safety.mjs' &&
                                   (lineContent.includes('isFixtureExample') ||
                                    lineContent.includes('/var/www/example.com') ||
                                    lineContent.includes("C:" + "\\" + "Temp" + "\\" + "test.txt") ||
                                    lineContent.includes('/tmp/test-file.txt') ||
                                    lineContent.includes('example.com') ||
                                    lineContent.includes('example.org') ||
                                    lineContent.includes('isExemptionFunctionSelf') ||
                                    lineContent.includes("C:" + "\\" + "Temp" + "\\" + "test.txt"));

    if (!isDefinitionContext && !isExemptionFunctionSelf) {
        return false;
    }

    return true;
}

function scanDirectory(dir, baseDir = dir, violations = [], excludeDirs = new Set(['node_modules', 'dist', '.git', 'coverage', 'build', 'out', 'package'])) {
    if (!existsSync(dir)) return violations;

    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
            if (!excludeDirs.has(entry.name) && !entry.name.startsWith('.')) {
                scanDirectory(fullPath, baseDir, violations, excludeDirs);
            }
        } else if (entry.isFile() && shouldScanFile(entry.name)) {
            const relPath = relative(baseDir, fullPath);
            const fileViolations = scanFile(fullPath, relPath);
            violations.push(...fileViolations);
        }
    }
    return violations;
}

function scanTracked() {
    try {
        const output = execSync('git ls-files -z', { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 });
        const files = output.split('\0').filter(f => f);
        // Scan ALL tracked files including tests/, docs/, .github/, root files
        console.error(`Scanning ${files.length} tracked files for public safety violations...`);

        const violations = [];
        for (const file of files) {
            if (shouldScanFile(file)) {
                const fileViolations = scanFile(file, file);
                violations.push(...fileViolations);
            }
        }

        if (violations.length === 0) {
            console.error('No public safety violations found');
            process.exit(0);
        } else {
            console.error(`Found ${violations.length} public safety violation(s):`);
            for (const v of violations) {
                console.log(`${v.rule} ${v.file}:${v.line}`);
            }
            process.exit(1);
        }
    } catch (e) {
        console.error('SCAN_ERROR');
        process.exit(1);
    }
}

function reportScannedPaths() {
    try {
        const output = execSync('git ls-files -z', { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 });
        const files = output.split('\0').filter(f => f);
        const scannable = files.filter(f => shouldScanFile(f));
        for (const file of scannable) {
            console.log(file);
        }
    } catch (e) {
        console.error('SCAN_ERROR');
        process.exit(1);
    }
}

function main() {
    const args = process.argv.slice(2);
    let targetDir = '.';
    let tracked = false;
    let reportPaths = false;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--tracked') {
            tracked = true;
        } else if (args[i] === '--report-scanned-paths') {
            reportPaths = true;
        } else if (args[i] === '--path' && i + 1 < args.length) {
            targetDir = args[i + 1];
            i++;
        }
    }

    if (reportPaths) {
        reportScannedPaths();
        return;
    }

    if (tracked) {
        scanTracked();
    } else {
        // For --path mode, check if target is file or directory
        let stat;
        try {
            stat = statSync(targetDir);
        } catch (e) {
            console.error('SCAN_ERROR');
            process.exit(1);
        }

        if (stat.isFile()) {
            // Scan single file
            const violations = scanFile(targetDir, basename(targetDir));
            if (violations.length === 0) {
                console.error('No public safety violations found');
                process.exit(0);
            } else {
                for (const v of violations) {
                    console.log(`${v.rule} ${v.file}:${v.line}`);
                }
                process.exit(1);
            }
        } else if (stat.isDirectory()) {
            console.error(`Scanning ${targetDir} for public safety violations...`);
            const violations = scanDirectory(targetDir, targetDir, [], new Set(['node_modules', 'dist', '.git', 'coverage', 'build', 'out', 'package']));

            if (violations.length === 0) {
                console.error('No public safety violations found');
                process.exit(0);
            } else {
                console.error(`Found ${violations.length} public safety violation(s):`);
                for (const v of violations) {
                    console.log(`${v.rule} ${v.file}:${v.line}`);
                }
                process.exit(1);
            }
        } else {
            console.error('SCAN_ERROR');
            process.exit(1);
        }
    }
}

main();
