## faults to unique

- paper_nibble_r15: mean 97.6, median 92, p90 132, p95 148, p99 191, max 297
- full_nibble_r15: mean 50.9, median 48, p90 69, p95 77, p99 97, max 145
- full_nibble_aligned_r15: mean 46.7, median 45, p90 61, p95 68, p99 82, max 122
- full_bit_r15: mean 102.9, median 99, p90 135, p95 148, p99 177, max 263
- full_byte_r15: mean 29.0, median 28, p90 40, p95 45, p99 57, max 96
- word_word_r15: mean 15.1, median 15, p90 19, p95 21, p99 25, max 35
- full_nibble_r14: mean 49.4, median 47, p90 66, p95 73, p99 88, max 139
- full_nibble_r13: mean 51.1, median 49, p90 69, p95 78, p99 96, max 160
- paper_nibble_r14: mean 95.5, median 91, p90 127, p95 139, p99 173, max 307
- paper_nibble_r13: mean 98.0, median 93, p90 131, p95 146, p99 184, max 307

## group relation (equations -> log2 candidates, % unique)

- paper: 16 eq -> 2^5.95, unique 0.0%
- paper: 20 eq -> 2^4.41, unique 0.3%
- paper: 27 eq -> 2^2.57, unique 5.3%
- paper: 36 eq -> 2^1.22, unique 28.2%
- paper: 45 eq -> 2^0.60, unique 54.9%
- full: 16 eq -> 2^1.91, unique 18.5%
- full: 20 eq -> 2^1.06, unique 40.8%
- full: 27 eq -> 2^0.38, unique 72.9%
- full: 36 eq -> 2^0.10, unique 91.9%
- full: 45 eq -> 2^0.03, unique 97.5%

## equation probability: max |emp-theory| = 0.0019

## master key

- full_36per_round: success 99.9%, faults mean 108 max 108, log2 k16 mean 3.09 max 22.5, tested mean 142.2 max 65536, solve ms mean 14.7 max 2964.8, pairs to reject wrong k16: {'mean': 1.817698549632974, 'min': 1.0, 'max': 8.0, 'n': 879, 'p50': 1.4666666666666666, 'p90': 3.0, 'p95': 4.0, 'p99': 6.0, 'stdev': 1.012808146573694} max 14
- full_48per_round: success 100.0%, faults mean 144 max 144, log2 k16 mean 0.89 max 13.5, tested mean 16.2 max 11520, solve ms mean 8.9 max 1066.2, pairs to reject wrong k16: {'mean': 2.1887606566290283, 'min': 1.0, 'max': 9.0, 'n': 474, 'p50': 2.0, 'p90': 4.0, 'p95': 5.0, 'p99': 6.333333333333333, 'stdev': 1.3414567304206102} max 14
- full_adaptive: success 100.0%, faults mean 150 max 279, log2 k16 mean 0.00 max 0.0, tested mean 1.0 max 1, solve ms mean 8.1 max 17.2, pairs to reject wrong k16: None max None
- paper_adaptive: success 100.0%, faults mean 291 max 520, log2 k16 mean 0.00 max 0.0, tested mean 1.0 max 1, solve ms mean 15.0 max 26.5, pairs to reject wrong k16: None max None
- paper_72per_round: success 100.0%, faults mean 216 max 216, log2 k16 mean 2.33 max 11.8, tested mean 22.3 max 3456, solve ms mean 12.7 max 357.5, pairs to reject wrong k16: {'mean': 2.0133733712197697, 'min': 1.0, 'max': 9.0, 'n': 848, 'p50': 1.574468085106383, 'p90': 3.6666666666666665, 'p95': 4.571428571428571, 'p99': 6.666666666666667, 'stdev': 1.240330759436295} max 17

## filter robustness

- single_pnd_in_z: accepted 100.00%, harmful 0/20000
- two_pnds_in_z: accepted 12.12%, harmful 4/20000
- random_word_in_z: accepted 0.00%, harmful 0/20000
- random_byte_window_in_z: accepted 18.17%, harmful 0/20000
- pnd_in_z_and_pnd_in_x: accepted 13.15%, harmful 2630/20000
- pnd_in_z_and_pnd_in_w: accepted 12.89%, harmful 2353/20000
- pnd_in_z_wrong_round_14: accepted 0.14%, harmful 19/20000
- pnd_in_z_wrong_round_16: accepted 0.00%, harmful 0/20000
- three_bit_L2_preimage: accepted 18.35%, harmful 3670/20000
