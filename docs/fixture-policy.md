# Fixture Policy

## Purpose

Define what test fixtures are permitted in the CopyMarker repository.

## Permitted Synthetic Fixtures

### Domains

Only reserved example domains (RFC 2606):

```
example.com
example.org
example.net
```

Subdomains are permitted:

```
api.example.com
test.example.org
sub.domain.example.net
```

### IP Addresses

Only reserved documentation ranges (RFC 5737, RFC 3849):

```
192.0.2.0/24      (TEST-NET-1)
198.51.100.0/24   (TEST-NET-2)
203.0.113.0/24    (TEST-NET-3)
2001:db8::/32     (IPv6 documentation)
```

### Email Addresses

Only addresses using permitted domains:

```
user@example.com
test@example.org
admin@example.net
```

### Placeholder Marker

Use `<redacted>` for any value that would be sensitive in production:

```
Authorization: Bearer <redacted>
Cookie: session=<redacted>
```

### File Paths

Only obviously synthetic paths:

```
/tmp/test-file.txt
/var/www/example.com
C:\Temp\test.txt
```

## Forbidden Fixtures

Do not commit:

- Real-looking API keys, tokens, or secrets
- Real email addresses or domains
- Real IP addresses (public or private)
- Real file paths from development machines
- Real browser profile paths
- Real service responses or HTML
- Any value that could be mistaken for a real secret

## Runtime Fixture Generation

Tests must generate secret-like positive cases at runtime in temporary directories.

Example:

```javascript
const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'copymarker-test-'));
await fs.writeFile(path.join(tempDir, 'secret.txt'), 'sk_test_FAKEKEY12345678901234567890');
```

Do not commit realistic secret strings as fixture files.
