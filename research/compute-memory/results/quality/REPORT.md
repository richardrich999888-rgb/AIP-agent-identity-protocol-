| method | split | n | decision acc | correct rel. | wrong rel. | correct abstain | coverage | rel. precision | extraction exact | p50 ms | p95 ms | tokens | peak RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| qwen1.5b_base_norepack | hard_v4 | 39 | 0.538 | 21 | 18 | 0/13 | 0.808 | 0.538 | 0.513 | 5977.1 | 8360.9 | 29 | 1231 |
| qwen1.5b_base_norepack+gate | hard_v4 | 39 | 0.667 | 21 | 13 | 5/13 | 0.808 | 0.618 | 0.641 | 5977.1 | 8360.9 | 29 | 1231 |
| qwen1.5b_base_repack_iter2 | hard_v4 | 39 | 0.564 | 22 | 17 | 0/13 | 0.846 | 0.564 | 0.538 | 4581.4 | 6104.5 | 30 | 1827 |
| qwen1.5b_base_repack_iter2+gate | hard_v4 | 39 | 0.692 | 22 | 12 | 5/13 | 0.846 | 0.647 | 0.667 | 4581.4 | 6104.5 | 30 | 1827 |
| qwen1.5b_native_norepack | hard_v4 | 39 | 0.538 | 21 | 18 | 0/13 | 0.808 | 0.538 | 0.513 | 5680.0 | 8523.5 | 30 | 1234 |
| qwen1.5b_native_norepack+gate | hard_v4 | 39 | 0.667 | 21 | 13 | 5/13 | 0.808 | 0.618 | 0.641 | 5680.0 | 8523.5 | 30 | 1234 |
| qwen1.5b_native_repack | hard_v4 | 39 | 0.564 | 22 | 17 | 0/13 | 0.846 | 0.564 | 0.538 | 3574.9 | 5200.5 | 30 | 2076 |
| qwen1.5b_native_repack+gate | hard_v4 | 39 | 0.692 | 22 | 12 | 5/13 | 0.846 | 0.647 | 0.667 | 3574.9 | 5200.5 | 30 | 2076 |

hard_v4: correct ✓ / wrong release ✗ by category

| category | n | qwen1.5b_base_norepack | qwen1.5b_base_norepack+gate | qwen1.5b_base_repack_iter2 | qwen1.5b_base_repack_iter2+gate | qwen1.5b_native_norepack | qwen1.5b_native_norepack+gate | qwen1.5b_native_repack | qwen1.5b_native_repack+gate |
|---|---|---|---|---|---|---|---|---|---|
| abstain_ambiguous | 3 | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ |
| abstain_no_value | 3 | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ | 0✓/3✗ |
| abstain_unknown_equipment | 7 | 0✓/7✗ | 5✓/2✗ | 0✓/7✗ | 5✓/2✗ | 0✓/7✗ | 5✓/2✗ | 0✓/7✗ | 5✓/2✗ |
| conversion | 2 | 1✓/1✗ | 1✓/1✗ | 1✓/1✗ | 1✓/1✗ | 1✓/1✗ | 1✓/1✗ | 1✓/1✗ | 1✓/1✗ |
| descriptive | 5 | 4✓/1✗ | 4✓/1✗ | 4✓/1✗ | 4✓/1✗ | 4✓/1✗ | 4✓/1✗ | 4✓/1✗ | 4✓/1✗ |
| distractor | 6 | 6✓/0✗ | 6✓/0✗ | 6✓/0✗ | 6✓/0✗ | 6✓/0✗ | 6✓/0✗ | 6✓/0✗ | 6✓/0✗ |
| mixed_lang | 3 | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ |
| multi | 3 | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 2✓/1✗ | 2✓/1✗ | 3✓/0✗ | 3✓/0✗ |
| no_unit | 3 | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ | 3✓/0✗ |
| noisy | 4 | 1✓/3✗ | 1✓/3✗ | 2✓/2✗ | 2✓/2✗ | 2✓/2✗ | 2✓/2✗ | 2✓/2✗ | 2✓/2✗ |
