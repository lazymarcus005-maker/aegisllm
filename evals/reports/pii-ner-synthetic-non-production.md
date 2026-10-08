# PII / NER span evaluation

- Schema: aegisllm.pii-eval/v1
- Dataset SHA-256: 7438b3cc75be997c36ca0b173a56c10fa7e154805483fc544ec355c46c7d149d
- Provider: fake
- Production eligible: false
- Examples: 3

| language | entity | gold | predicted | exact P | exact R | exact FNR | overlap P | overlap R | overlap FNR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| en | ADDRESS | 1 | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |
| en | PERSON | 1 | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |
| mixed | BANK_ACCOUNT | 1 | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |
| mixed | PERSON | 1 | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |
| th | ADDRESS | 1 | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |
| th | PERSON | 1 | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.000 |

Calibration candidates: [0.5 0.9]

> NON-PRODUCTION: synthetic/fake provider or dataset. Do not use this report for model promotion.
