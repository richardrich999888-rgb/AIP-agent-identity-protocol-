| config | prefill@128 | prefill@512 | prefill@1.5k | decode (256 gen) | peak RSS MB | private MB | file MB |
|---|---|---|---|---|---|---|---|
| 0.5b-q4 | 169.1 | 146.9 | 128.6 | 28.4 | 752 | 400 | 335 |
| 0.5b-q8 | 500.9 | 442.2 | 338.9 | 43.3 | 1262 | 734 | 511 |
| 1.5b-q4 | 109.2 | 98.8 | 90.8 | 10.5 | 2085 | 1198 | 887 |
| 1.5b-q8 | 147.4 | 136.2 | 118.1 | 13.9 | 3613 | 1995 | 1573 |
| 1.5b-q4_base_norepack | 33.7 | 33.4 | 31.2 | 9.5 | 1316 | 247 | 1069 |
| 1.5b-q4_base_repack | 47.9 | 49.2 | 45.9 | 10.6 | 1912 | 843 | 1069 |
| 1.5b-q4_native_norepack | 36.2 | 36.5 | 35.1 | 10.1 | 1318 | 247 | 1070 |
| 1.5b-q4_native_repack | 105.1 | 102.9 | 88.0 | 11.0 | 2086 | 1198 | 888 |

| model | mode | load s (median) | peak RSS MB | private MB | file MB |
|---|---|---|---|---|---|
| 0.5b-q4 | mmap cold | 0.97 | 754 | 341 | 336 |
| 0.5b-q4 | mmap warm | 0.47 | 754 | 341 | 336 |
| 0.5b-q4 | no-mmap cold | 0.83 | 606 | 596 | 11 |
| 0.5b-q4 | no-mmap warm | 1.01 | 606 | 596 | 11 |
| 0.5b-q8 | mmap cold | 1.10 | 1264 | 675 | 511 |
| 0.5b-q8 | mmap warm | 0.62 | 1264 | 675 | 511 |
| 0.5b-q8 | no-mmap cold | 1.81 | 824 | 813 | 10 |
| 0.5b-q8 | no-mmap warm | 0.83 | 824 | 813 | 10 |
| 1.5b-q4 | mmap cold | 1.95 | 2077 | 1141 | 888 |
| 1.5b-q4 | mmap warm | 1.10 | 2076 | 1141 | 888 |
| 1.5b-q4 | no-mmap cold | 1.64 | 1277 | 1267 | 11 |
| 1.5b-q4 | no-mmap warm | 1.19 | 1277 | 1267 | 10 |
| 1.5b-q8 | mmap cold | 2.34 | 3614 | 1938 | 1575 |
| 1.5b-q8 | mmap warm | 1.85 | 3615 | 1938 | 1575 |
| 1.5b-q8 | no-mmap cold | 3.49 | 2186 | 2175 | 10 |
| 1.5b-q8 | no-mmap warm | 2.82 | 2186 | 2175 | 10 |

| prefix cache | evaluated tokens (median, requests 2..n) | prefill ms | wall s |
|---|---|---|---|
| cache_off | 1236 | 13623 | 14.39 |
| cache_on | 33 | 668 | 1.36 |

| cache mode | attacker AUC | median hit s | median miss s | victim 2nd-request tokens (median) |
|---|---|---|---|---|
| unprotected | 1.00 | 0.16 | 8.40 | 406 |
| scoped | 0.43 | 8.29 | 8.26 | 808 |

| tokens | recompute s | restore s | file MB |
|---|---|---|---|
| 512 | 5.40 | 0.007 | 14.0 |
| 1536 | 18.00 | 0.017 | 42.0 |
| 3000 | 38.42 | 0.034 | 82.1 |

| speculative | decode tok/s | accepted/drafted | peak RSS MB | outputs identical |
|---|---|---|---|---|
| baseline | 11.46 | 0/0 | 2074 | 0/3 |
| draft | 10.76 | 199/251 | 2736 | 0/3 |

shared mapping: solo RSS 2014 PSS 1607; pair PSS 1435+1435, private 1128 each
