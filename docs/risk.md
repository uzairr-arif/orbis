# The Orbis risk model

Raw severity is a poor prioritization signal: it treats a localhost-only dev
dependency and an internet-facing production service as equally urgent. Orbis
scores context instead.

## Formula

```text
risk = severity x exposure x exploitability x criticality x confidence
```

## Weights (v0.1)

| Factor | Value | Weight |
|---|---|---|
| severity | critical / high / medium / low / info | 1.0 / 0.7 / 0.4 / 0.2 / 0.1 |
| exposure | internet / local network / localhost / unknown | 1.0 / 0.6 / 0.5 / 0.5 |
| exploitability | high / medium / low / unknown | 1.0 / 0.7 / 0.6 / 0.6 |
| criticality | production / staging / development / unknown | 1.0 / 0.7 / 0.7 / 0.7 |
| confidence | 0.0 to 1.0 | as reported by the source tool |

## Thresholds

| Composite score | Orbis risk |
|---|---|
| >= 0.60 | critical |
| >= 0.35 | high |
| >= 0.12 | medium |
| >= 0.05 | low |
| below | info |

Worked example, the same CVSS 8.2 (high) package vulnerability:

- Internet-facing production host, exploit available, confidence 0.98:
  0.7 x 1.0 x 1.0 x 1.0 x 0.98 = **0.69, critical**
- Localhost-only dev box, no practical exploit, confidence 0.98:
  0.7 x 0.5 x 0.6 x 0.7 x 0.98 = **0.14, medium**

## Security score

```text
score = 100 - (12 x critical + 5 x high + 2 x medium + 0.5 x low)
```

Penalties are counted by Orbis risk level, not raw severity, so context
downgrades are reflected in the score. Clamped to 0-100.

One number is not objective truth. The score is a trend line: watch it move
between scans (`orbis diff` in v0.2), do not worship it.

## Roadmap

- v0.2: weights move from code into `rules/` as declarative rule files.
- v0.2: correlation upgrades context (an open port plus weak SSH auth becomes
  one attack path with internet exposure and high exploitability).
