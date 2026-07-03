# Prior Ablation Replay

Fixtures: 80

| mode | pass_rate | mean_entropy | mean_max_prior | top_k_hit |
|------|-----------|--------------|----------------|-----------|
| full | 1.0 | 1.3369 | 0.2777 | 1.0 |
| no_flow | 0.8 | 0.658 | 0.5401 | 0.4 |
| no_sigma | 1.0 | 1.3369 | 0.2777 | 1.0 |
| no_dual_use | 0.988 | 1.049 | 0.3684 | 1.0 |
| no_lifecycle | 0.938 | 1.032 | 0.3731 | 0.9 |