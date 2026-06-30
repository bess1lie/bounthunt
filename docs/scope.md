# Scope

Every network action in bountyhunt is gated by a YAML scope file. A target
that is not in scope is refused **before** any request leaves the host.

## File format

```yaml
allow:
  - "*.example.com"
  - "api.example.org"

deny:
  - "admin.example.com"
```

- `allow` — list of domains that may be scanned and whose results are kept.
- `deny` — list of domains that are always refused, even if they match an
  `allow` rule. The deny list is checked **first**.

## Creating a template

```bash
bountyhunt init scope.yaml
```

This writes the template shown above to `scope.yaml`. Edit it with your
program's domains before running a scan.

## Wildcard semantics

Bountyhunt has two distinct matching methods that interpret wildcards
differently. This is intentional.

| Pattern | `is_in_scope(domain)` | `can_scan(domain)` |
|---|---|---|
| `*.example.com` | matches `sub.example.com` only — **not** `example.com` | matches `sub.example.com` **and** `example.com` |
| `example.com` | matches `example.com` and all its subdomains | same |

### Why the difference

- `can_scan(target)` is the **go/no-go gate** for launching recon. When you
  write `allow: ["*.example.com"]` you usually still want to point subfinder
  at the bare `example.com` so it can discover subdomains. `can_scan` permits
  the root as a valid scan target for wildcards.
- `is_in_scope(domain)` is the **final decision** for keeping a discovered
  host in the results. A wildcard `*.example.com` means "subdomains only", so
  the bare `example.com` returned by subfinder is filtered out unless you also
  list it in `allow`.

### Practical example

```yaml
allow:
  - "*.kazgasa.kz"
  - "kazgasa.kz"
deny: []
```

- `can_scan("kazgasa.kz")` → True (you explicitly allow it)
- `can_scan("www.kazgasa.kz")` → True (matches the wildcard)
- `can_scan("evil.com")` → False
- `is_in_scope("www.kazgasa.kz")` → True
- `is_in_scope("kazgasa.kz")` → True (explicitly listed)
- `is_in_scope("evil.com")` → False

If your `allow` only had `*.kazgasa.kz` (without the bare domain), then
`is_in_scope("kazgasa.kz")` would be **False** but `can_scan("kazgasa.kz")`
would still be **True** — recon runs, but the bare apex is dropped from
results.

## Deny examples

```yaml
allow:
  - "*.example.com"
deny:
  - "admin.example.com"
  - "mail.example.com"
```

- `can_scan("admin.example.com")` → False (denied, even though it matches the
  wildcard)
- `is_in_scope("admin.example.com")` → False

## Loading a scope

`scan` and `monitor` take the scope file as their first argument:

```bash
bountyhunt scan scope.yaml --all
bountyhunt monitor scope.yaml
```

If the file is missing, bountyhunt exits with a `FileNotFoundError`. If it is
present but both `allow` and `deny` are empty, bountyhunt raises a
`ValueError`.

## Single-target override

`scan --target` and `monitor --target` let you scan one specific domain
without reading it from the scope file. The scope file is still required and
`can_scan(target)` is still enforced — a target outside scope is refused.
