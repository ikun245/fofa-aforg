# fofa-afrog

An interactive CLI that chains **FOFA** asset discovery with **afrog** vulnerability scanning.

```
FOFA query  →  numbered results table  →  target selection  →  afrog scan  →  JSON report
```

## Features

- Credentials saved once to `~/.fofa-afrog.json` (mode 0600)
- Numbered step headers so you always know where you are in the workflow
- Keyword filter on FOFA results before selecting targets
- Deduplicates targets automatically
- Coloured live output per severity (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- Severity breakdown in the final summary
- JSON export of all findings

## Requirements

- Go 1.21+
- A [FOFA](https://fofa.info) account (email + API key)
- [afrog POC collection](https://github.com/zan8in/afrog-pocs) cloned locally

## Build

```bash
# If proxy.golang.org is unreachable in your region:
GOPROXY=https://goproxy.cn,direct go mod tidy
GOPROXY=https://goproxy.cn,direct go build -o fofa-afrog ./cmd/fofa-afrog/
```

## Usage

```bash
./fofa-afrog
```

The tool walks you through 8 steps interactively:

| Step | Action |
|------|--------|
| 1 | Load / enter FOFA credentials |
| 2 | Enter FOFA query and result size |
| 3 | Fetch and display results table |
| 4 | Optional keyword filter on the table |
| 5 | Select targets (numbers, ranges, or `all`) |
| 6 | Configure POC path, severity, keyword |
| 7 | Run afrog scan with live output |
| 8 | Summary + JSON export |

## Example queries

```
app="Apache-Shiro"
title="Nacos" && country="CN"
app="Spring-Boot" && status_code="200"
```

## Legal notice

Only scan systems you own or have **explicit written authorization** to test.
Unauthorized scanning is illegal in most jurisdictions.

## Credits

Vulnerability scanning powered by [afrog](https://github.com/zan8in/afrog) by zan8in.
