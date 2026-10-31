| method | split | n | acc [95% CI] | macro-F1 | ECE | Brier | AURC | p50 ms | p95 ms | p99 ms | dec/s | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cascade[symbolic→qwen1.5b/extract_json] | test_para | 300 | 0.977 [0.957, 0.993] | 0.976 | 0.023 | 0.047 | 0.031 | 3292.87 | 3537.44 | 3621.62 | 0.3 | escalated 271 |
| cascade[symbolic→qwen1.5b/extract_json] | test_ood | 300 | 1.000 [1.000, 1.000] | 1.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.01 | 0.02 | 182611.6 | escalated 0 |
| cascade[symbolic→qwen1.5b/extract_readout] | test_id | 300 | 1.000 [1.000, 1.000] | 1.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.02 | 0.03 | 180060.9 | escalated 0 |
| cascade[symbolic→qwen1.5b/extract_readout] | test_para | 300 | 0.783 [0.733, 0.827] | 0.760 | 0.217 | 0.433 | 0.246 | 826.71 | 993.26 | 1064.72 | 1.3 | escalated 271 |
| cascade[symbolic→qwen1.5b/extract_readout] | test_ood | 300 | 1.000 [1.000, 1.000] | 1.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.01 | 0.02 | 182611.6 | escalated 0 |
| cascade[symbolic→qwen1.5b/readout] | test_id | 300 | 1.000 [1.000, 1.000] | 1.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.02 | 0.03 | 180060.9 | escalated 0 |
| cascade[symbolic→qwen1.5b/readout] | test_para | 300 | 0.423 [0.373, 0.477] | 0.317 | 0.577 | 1.153 | 0.608 | 1026.36 | 1153.92 | 1211.84 | 1.1 | escalated 271 |
| cascade[symbolic→qwen1.5b/readout] | test_ood | 300 | 1.000 [1.000, 1.000] | 1.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.01 | 0.02 | 182611.6 | escalated 0 |
| cascade[symbolic→tfidf] | test_id | 300 | 1.000 [1.000, 1.000] | 1.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.02 | 0.03 | 180060.9 | escalated 0 |
| cascade[symbolic→tfidf] | test_para | 300 | 0.903 [0.870, 0.937] | 0.896 | 0.039 | 0.160 | 0.025 | 1.62 | 2.72 | 3.25 | 601.0 | escalated 271 |
| cascade[symbolic→tfidf] | test_ood | 300 | 1.000 [1.000, 1.000] | 1.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.01 | 0.02 | 182611.6 | escalated 0 |
| qwen0.5b/json_decision_first | test_id | 60 | 0.283 [0.183, 0.400] | 0.187 | 0.717 | 1.433 | 0.697 | 2157.01 | 2903.89 | 2990.94 | 0.4 | 36 gen tokens |
| qwen0.5b/json_decision_first | test_para | 60 | 0.317 [0.200, 0.433] | 0.216 | 0.683 | 1.367 | 0.743 | 2027.41 | 2669.46 | 2778.15 | 0.5 | 37 gen tokens |
| qwen0.5b/json_decision_first | test_ood | 60 | 0.283 [0.167, 0.400] | 0.190 | 0.717 | 1.433 | 0.730 | 2693.77 | 3973.25 | 4358.85 | 0.4 | 41 gen tokens |
| qwen0.5b/readout_v1_invalid | test_id | 300 | 0.260 [0.213, 0.310] | 0.167 | 0.015 | 0.750 | 0.773 | 343.79 | 417.74 | 435.98 | 2.9 |  |
| qwen0.5b/readout_v1_invalid | test_para | 300 | 0.247 [0.200, 0.293] | 0.155 | 0.024 | 0.748 | 0.750 | 336.47 | 413.19 | 457.91 | 3.0 |  |
| qwen0.5b/readout_v1_invalid | test_ood | 300 | 0.400 [0.350, 0.453] | 0.157 | 0.123 | 0.741 | 0.644 | 684.45 | 1080.69 | 1200.05 | 1.4 |  |
| qwen1.5b/extract_json | test_para | 300 | 0.977 [0.957, 0.993] | 0.976 | 0.023 | 0.047 | 0.031 | 3312.84 | 3547.92 | 3628.44 | 0.3 |  |
| qwen1.5b/extract_json | test_ood | 300 | 0.607 [0.550, 0.660] | 0.572 | 0.393 | 0.787 | 0.396 | 6627.92 | 8528.74 | 9471.14 | 0.2 |  |
| qwen1.5b/extract_readout | test_id | 300 | 0.897 [0.863, 0.927] | 0.881 | 0.103 | 0.207 | 0.099 | 871.04 | 993.08 | 1060.56 | 1.1 | label mass 0.00 |
| qwen1.5b/extract_readout | test_para | 300 | 0.783 [0.733, 0.827] | 0.760 | 0.217 | 0.433 | 0.246 | 842.21 | 995.77 | 1071.25 | 1.2 | label mass 1.00 |
| qwen1.5b/extract_readout | test_ood | 300 | 0.490 [0.433, 0.540] | 0.350 | 0.233 | 0.743 | 0.416 | 1500.92 | 2149.94 | 2292.35 | 0.7 | abstained 241; label mass 1.00 |
| qwen1.5b/extract_readout_logprob_invalid | test_id | 300 | 0.357 [0.303, 0.413] | 0.316 | 0.416 | 0.968 | 0.470 | 878.53 | 985.54 | 1076.35 | 1.1 | label mass 0.00 |
| qwen1.5b/extract_readout_logprob_invalid | test_para | 300 | 0.567 [0.507, 0.620] | 0.567 | 0.291 | 0.667 | 0.194 | 843.84 | 989.67 | 1027.34 | 1.2 | label mass 1.00 |
| qwen1.5b/extract_readout_logprob_invalid | test_ood | 300 | 0.430 [0.373, 0.480] | 0.269 | 0.249 | 0.764 | 0.524 | 1498.44 | 2156.71 | 2259.67 | 0.7 | abstained 241; label mass 1.00 |
| qwen1.5b/json_decision_first | test_id | 60 | 0.250 [0.150, 0.367] | 0.126 | 0.750 | 1.500 | 0.716 | 6291.74 | 8430.09 | 8551.05 | 0.2 | 50 gen tokens |
| qwen1.5b/json_decision_first | test_para | 60 | 0.233 [0.133, 0.333] | 0.100 | 0.767 | 1.533 | 0.716 | 6082.00 | 7589.73 | 7795.11 | 0.2 | 50 gen tokens |
| qwen1.5b/json_decision_first | test_ood | 60 | 0.267 [0.150, 0.367] | 0.132 | 0.733 | 1.467 | 0.712 | 6861.45 | 9206.39 | 10196.30 | 0.1 | 52 gen tokens |
| qwen1.5b/json_reason_first | test_id | 60 | 0.317 [0.200, 0.433] | 0.234 | 0.683 | 1.367 | 0.633 | 7721.02 | 8863.45 | 10037.17 | 0.1 | 66 gen tokens |
| qwen1.5b/json_reason_first | test_para | 60 | 0.233 [0.133, 0.350] | 0.153 | 0.767 | 1.533 | 0.702 | 7796.06 | 8710.90 | 9493.22 | 0.1 | 68 gen tokens |
| qwen1.5b/json_reason_first | test_ood | 60 | 0.267 [0.150, 0.383] | 0.182 | 0.733 | 1.467 | 0.657 | 8859.00 | 11433.34 | 12542.73 | 0.1 | 74 gen tokens |
| qwen1.5b/readout | test_id | 300 | 0.357 [0.303, 0.410] | 0.205 | 0.643 | 1.287 | 0.622 | 1053.65 | 1194.13 | 1307.28 | 0.9 | label mass 1.00 |
| qwen1.5b/readout | test_para | 300 | 0.343 [0.293, 0.397] | 0.199 | 0.657 | 1.313 | 0.673 | 1042.19 | 1163.23 | 1226.80 | 1.0 | label mass 1.00 |
| qwen1.5b/readout | test_ood | 300 | 0.277 [0.227, 0.327] | 0.167 | 0.723 | 1.447 | 0.706 | 1721.55 | 2390.39 | 2502.13 | 0.6 | label mass 1.00 |
| qwen1.5b/readout_nocache_v2_logprob_invalid | test_id | 60 | 0.250 [0.150, 0.367] | 0.162 | 0.544 | 1.197 | 0.755 | 7948.46 | 8375.93 | 8422.52 | 0.1 | label mass 1.00 |
| qwen1.5b/readout_nocache_v2_logprob_invalid | test_para | 60 | 0.283 [0.167, 0.400] | 0.189 | 0.544 | 1.232 | 0.815 | 7917.72 | 8340.44 | 8530.46 | 0.1 | label mass 1.00 |
| qwen1.5b/readout_nocache_v2_logprob_invalid | test_ood | 60 | 0.217 [0.117, 0.317] | 0.140 | 0.545 | 1.190 | 0.808 | 8656.50 | 9509.26 | 9724.85 | 0.1 | label mass 1.00 |
| qwen1.5b/readout_v1_invalid | test_id | 300 | 0.350 [0.297, 0.407] | 0.181 | 0.048 | 0.727 | 0.648 | 724.65 | 837.71 | 909.80 | 1.4 |  |
| qwen1.5b/readout_v1_invalid | test_para | 300 | 0.367 [0.317, 0.417] | 0.184 | 0.066 | 0.720 | 0.618 | 694.55 | 846.73 | 974.92 | 1.5 |  |
| qwen1.5b/readout_v1_invalid | test_ood | 300 | 0.240 [0.190, 0.287] | 0.138 | 0.111 | 0.752 | 0.720 | 1399.82 | 2114.90 | 2307.58 | 0.7 |  |
| qwen1.5b/readout_v2_logprob_invalid | test_id | 300 | 0.357 [0.303, 0.410] | 0.205 | 0.087 | 0.721 | 0.581 | 1110.00 | 1254.61 | 1304.43 | 0.9 | label mass 1.00 |
| qwen1.5b/readout_v2_logprob_invalid | test_para | 300 | 0.343 [0.293, 0.397] | 0.199 | 0.047 | 0.741 | 0.654 | 1088.44 | 1242.82 | 1290.68 | 0.9 | label mass 1.00 |
| qwen1.5b/readout_v2_logprob_invalid | test_ood | 300 | 0.277 [0.227, 0.327] | 0.167 | 0.071 | 0.734 | 0.749 | 1780.15 | 2476.63 | 2608.05 | 0.6 | label mass 1.00 |
| symbolic | test_id | 300 | 1.000 [1.000, 1.000] | 1.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.02 | 0.03 | 180060.9 |  |
| symbolic | test_para | 300 | 0.293 [0.240, 0.343] | 0.219 | 0.029 | 0.677 | 0.518 | 0.00 | 0.00 | 0.02 | 354929.2 | abstained 271 |
| symbolic | test_ood | 300 | 1.000 [1.000, 1.000] | 1.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.01 | 0.02 | 182611.6 |  |
| tfidf | test_id | 300 | 0.867 [0.827, 0.903] | 0.857 | 0.073 | 0.218 | 0.051 | 1.64 | 2.41 | 3.37 | 573.6 |  |
| tfidf | test_para | 300 | 0.897 [0.863, 0.930] | 0.891 | 0.051 | 0.170 | 0.032 | 1.68 | 2.75 | 3.25 | 543.8 |  |
| tfidf | test_ood | 300 | 0.440 [0.380, 0.493] | 0.470 | 0.318 | 0.829 | 0.542 | 1.88 | 2.96 | 3.57 | 430.4 |  |

| comparison | n | Δacc (readout − json) [95% CI] | P(readout ≤ json) | p95 readout ms | p95 json ms | p95 reduction | throughput × |
|---|---|---|---|---|---|---|---|
| qwen1.5b: readout vs json_decision_first [test_id] | 60 | +0.017 [-0.117, +0.150] | 0.454 | 1235 | 8430 | 85% | 5.3 |
| qwen1.5b: readout vs json_decision_first [test_para] | 60 | +0.050 [-0.083, +0.183] | 0.281 | 1124 | 7590 | 85% | 5.7 |
| qwen1.5b: readout vs json_decision_first [test_ood] | 60 | -0.050 [-0.200, +0.100] | 0.786 | 2345 | 9206 | 75% | 4.0 |
| qwen1.5b: readout vs json_reason_first [test_id] | 60 | -0.050 [-0.200, +0.083] | 0.784 | 1235 | 8863 | 86% | 6.3 |
| qwen1.5b: readout vs json_reason_first [test_para] | 60 | +0.050 [-0.100, +0.200] | 0.297 | 1124 | 8711 | 87% | 7.6 |
| qwen1.5b: readout vs json_reason_first [test_ood] | 60 | -0.050 [-0.200, +0.100] | 0.793 | 2345 | 11433 | 79% | 5.1 |

| method | server peak RSS MB | client peak RSS MB | temperature |
|---|---|---|---|
| cascade[symbolic→qwen1.5b/extract_json] | 1830.2890625 | 150.4 | — |
| cascade[symbolic→qwen1.5b/extract_readout] | 1821.37890625 | 150.3 | — |
| cascade[symbolic→qwen1.5b/readout] | 1821.3671875 | 150.5 | — |
| cascade[symbolic→tfidf] | — | 160.7 | 0.684 |
| qwen0.5b/json_decision_first | 646.4140625 | 150.0 | — |
| qwen0.5b/readout_v1_invalid | 621.0234375 | 150.6 | 13.511 |
| qwen1.5b/extract_json | 1830.2890625 | 150.4 | — |
| qwen1.5b/extract_readout | 1821.37890625 | 150.3 | — |
| qwen1.5b/extract_readout_logprob_invalid | 1794.7421875 | 149.5 | — |
| qwen1.5b/json_decision_first | 1865.140625 | 150.1 | — |
| qwen1.5b/json_reason_first | 1868.79296875 | 150.1 | — |
| qwen1.5b/readout | 1821.3671875 | 150.5 | — |
| qwen1.5b/readout_nocache_v2_logprob_invalid | 1877.69921875 | 150.3 | 1.0 |
| qwen1.5b/readout_v1_invalid | 1836.41015625 | 150.9 | 2.803 |
| qwen1.5b/readout_v2_logprob_invalid | 1820.69921875 | 150.8 | 7.451 |
| symbolic | — | 146.5 | — |
| tfidf | — | 160.7 | 0.684 |
