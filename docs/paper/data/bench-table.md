# Benchmark results

Source: `target/criterion` (criterion 0.5 estimates.json).
Generated: 2026-04-30T17:23:29Z by `scripts/bench-report.sh`.

Values are **median** wall-time per iteration with the 95% CI.
Run `cargo bench --manifest-path core/graph-engine/Cargo.toml` first.

| Benchmark | Case | Median | 95% CI |
|-----------|------|-------:|:-------|
| ba-any-2hop | v=1000,m=4 | 2.833 ms | [2.771 ms, 2.946 ms] |
| ba-any-2hop | v=10000,m=4 | 4.027 ms | [3.864 ms, 4.293 ms] |
| ba-typed-2hop | v=1000,m=4 | 66.477 µs | [63.562 µs, 68.949 µs] |
| ba-typed-2hop | v=10000,m=4 | 190.697 µs | [183.100 µs, 197.961 µs] |
| dedup-score-paginate | 100x25 | 713.115 µs | [712.449 µs, 715.284 µs] |
| dedup-score-paginate | 10x100 | 401.289 µs | [382.888 µs, 428.444 µs] |
| dedup-score-paginate | 50x50 | 672.790 µs | [670.673 µs, 675.737 µs] |
| ingest-sysmon-ndjson | 1000 | 4.738 ms | [4.447 ms, 4.861 ms] |
| ingest-sysmon-ndjson | 10000 | 38.792 ms | [38.494 ms, 39.132 ms] |
| ingest-sysmon-ndjson | 50000 | 204.436 ms | [202.643 ms, 206.920 ms] |
| lftj | v=1000,e=19936,t=1298 | 7.489 ms | [7.300 ms, 7.851 ms] |
| lftj | v=1000,e=19936,t=7811 | 5.381 ms | [5.376 ms, 5.383 ms] |
| lftj | v=1000,e=49535,t=121337 | 41.921 ms | [40.937 ms, 43.952 ms] |
| lftj | v=1000,e=49535,t=20350 | 57.420 ms | [56.625 ms, 58.603 ms] |
| lftj | v=1000,e=4969,t=109 | 449.769 µs | [449.457 µs, 450.394 µs] |
| lftj | v=1000,e=4969,t=18 | 644.041 µs | [626.807 µs, 687.614 µs] |
| lftj | v=2000,e=39554,t=1303 | 15.073 ms | [14.292 ms, 15.530 ms] |
| lftj | v=2000,e=39554,t=7768 | 13.744 ms | [13.104 ms, 14.471 ms] |
| lftj | v=500,e=2439,t=113 | 213.277 µs | [210.687 µs, 220.530 µs] |
| lftj | v=500,e=2439,t=26 | 297.164 µs | [288.484 µs, 303.560 µs] |
| lftj+simd | v=1000,e=19936,c6=63267586 | 27.625 s | [27.332 s, 28.159 s] |
| lftj+simd | v=1000,e=19936,k4=0 | 9.587 ms | [9.387 ms, 9.714 ms] |
| lftj+simd | v=1000,e=19936,k4=64 | 3.905 ms | [3.888 ms, 3.913 ms] |
| lftj+simd | v=1000,e=19936,k5=0 | 3.755 ms | [3.752 ms, 3.761 ms] |
| lftj+simd | v=1000,e=19936,t=1298 | 4.923 ms | [4.810 ms, 5.097 ms] |
| lftj+simd | v=1000,e=19936,t=7811 | 3.495 ms | [3.491 ms, 3.504 ms] |
| lftj+simd | v=1000,e=49535,k4=14892 | 47.294 ms | [46.867 ms, 49.240 ms] |
| lftj+simd | v=1000,e=49535,k4=23 | 36.252 ms | [35.885 ms, 36.785 ms] |
| lftj+simd | v=1000,e=49535,k5=89 | 28.435 ms | [27.816 ms, 31.874 ms] |
| lftj+simd | v=1000,e=49535,t=121337 | 11.842 ms | [11.511 ms, 12.211 ms] |
| lftj+simd | v=1000,e=49535,t=20350 | 17.930 ms | [17.360 ms, 18.121 ms] |
| lftj+simd | v=1000,e=4969,c6=15464 | 33.473 ms | [33.358 ms, 33.588 ms] |
| lftj+simd | v=1000,e=4969,k4=0 | 303.523 µs | [302.222 µs, 304.431 µs] |
| lftj+simd | v=1000,e=4969,t=109 | 294.705 µs | [294.311 µs, 295.146 µs] |
| lftj+simd | v=1000,e=4969,t=18 | 395.529 µs | [385.883 µs, 403.683 µs] |
| lftj+simd | v=1000,e=9913,c6=926763 | 731.633 ms | [730.917 ms, 732.616 ms] |
| lftj+simd | v=1000,e=9913,k4=0 | 2.531 ms | [2.501 ms, 2.572 ms] |
| lftj+simd | v=1000,e=9913,k4=1 | 1.027 ms | [1.024 ms, 1.029 ms] |
| lftj+simd | v=1000,e=9913,k5=0 | 1.015 ms | [1.015 ms, 1.016 ms] |
| lftj+simd | v=1000,e=99741,k4=977789 | 526.288 ms | [518.118 ms, 533.731 ms] |
| lftj+simd | v=1000,e=99741,k5=96211 | 511.238 ms | [497.642 ms, 520.842 ms] |
| lftj+simd | v=2000,e=39554,t=1303 | 9.579 ms | [9.409 ms, 9.874 ms] |
| lftj+simd | v=2000,e=39554,t=7768 | 8.546 ms | [8.383 ms, 8.963 ms] |
| lftj+simd | v=2000,e=79333,k4=1042 | 44.942 ms | [43.888 ms, 46.224 ms] |
| lftj+simd | v=500,e=2439,t=113 | 130.188 µs | [129.608 µs, 130.999 µs] |
| lftj+simd | v=500,e=2439,t=26 | 185.087 µs | [182.069 µs, 190.010 µs] |
| lftj+simd+canonical | v=1000,e=19936,k4=64 | 1.823 ms | [1.817 ms, 1.825 ms] |
| lftj+simd+canonical | v=1000,e=19936,k5=0 | 1.805 ms | [1.803 ms, 1.808 ms] |
| lftj+simd+canonical | v=1000,e=19936,t=7811 | 859.947 µs | [856.012 µs, 865.330 µs] |
| lftj+simd+canonical | v=1000,e=4969,c6=15464 | 7.646 ms | [7.622 ms, 7.661 ms] |
| lftj+simd+canonical | v=1000,e=4969,k4=0 | 155.204 µs | [154.693 µs, 155.814 µs] |
| lftj+simd+canonical | v=1000,e=4969,t=109 | 68.882 µs | [68.404 µs, 69.335 µs] |
| lftj+simd+canonical | v=1000,e=9913,c6=926763 | 147.219 ms | [147.034 ms, 147.595 ms] |
| lftj+simd+canonical | v=1000,e=9913,k4=1 | 502.055 µs | [500.509 µs, 504.033 µs] |
| lftj+simd+canonical | v=1000,e=9913,k5=0 | 511.241 µs | [510.836 µs, 511.729 µs] |
| lftj+simd+canonical | v=500,e=2439,t=113 | 26.147 µs | [26.135 µs, 26.263 µs] |
| lftj+simd+canonical+par | v=1000,e=19936,k4=64 | 307.153 µs | [304.774 µs, 308.817 µs] |
| lftj+simd+canonical+par | v=1000,e=19936,k5=0 | 314.534 µs | [312.965 µs, 316.660 µs] |
| lftj+simd+canonical+par | v=1000,e=19936,t=7811 | 154.171 µs | [153.359 µs, 156.156 µs] |
| lftj+simd+canonical+par | v=1000,e=4969,c6=15464 | 1.196 ms | [1.189 ms, 1.204 ms] |
| lftj+simd+canonical+par | v=1000,e=4969,k4=0 | 51.002 µs | [50.602 µs, 51.710 µs] |
| lftj+simd+canonical+par | v=1000,e=4969,t=109 | 40.098 µs | [39.943 µs, 40.421 µs] |
| lftj+simd+canonical+par | v=1000,e=9913,c6=926763 | 22.478 ms | [22.415 ms, 22.581 ms] |
| lftj+simd+canonical+par | v=1000,e=9913,k4=1 | 105.982 µs | [105.347 µs, 107.675 µs] |
| lftj+simd+canonical+par | v=1000,e=9913,k5=0 | 109.671 µs | [108.747 µs, 111.953 µs] |
| lftj+simd+canonical+par | v=500,e=2439,t=113 | 28.751 µs | [28.382 µs, 29.334 µs] |
| lftj+simd+par | v=1000,e=19936,c6=63267586 | 4.295 s | [4.146 s, 4.375 s] |
| lftj+simd+par | v=1000,e=19936,k4=0 | 2.144 ms | [2.047 ms, 2.249 ms] |
| lftj+simd+par | v=1000,e=19936,k4=64 | 626.309 µs | [625.015 µs, 629.973 µs] |
| lftj+simd+par | v=1000,e=19936,k5=0 | 614.299 µs | [611.900 µs, 617.617 µs] |
| lftj+simd+par | v=1000,e=49535,k4=14892 | 9.514 ms | [8.611 ms, 10.976 ms] |
| lftj+simd+par | v=1000,e=49535,k4=23 | 6.964 ms | [6.827 ms, 7.305 ms] |
| lftj+simd+par | v=1000,e=49535,k5=89 | 5.333 ms | [4.989 ms, 6.457 ms] |
| lftj+simd+par | v=1000,e=4969,c6=15464 | 4.987 ms | [4.952 ms, 5.074 ms] |
| lftj+simd+par | v=1000,e=4969,k4=0 | 84.137 µs | [78.991 µs, 90.025 µs] |
| lftj+simd+par | v=1000,e=9913,c6=926763 | 112.946 ms | [112.357 ms, 113.534 ms] |
| lftj+simd+par | v=1000,e=9913,k4=0 | 1.094 ms | [975.070 µs, 1.166 ms] |
| lftj+simd+par | v=1000,e=9913,k4=1 | 188.883 µs | [186.756 µs, 191.538 µs] |
| lftj+simd+par | v=1000,e=9913,k5=0 | 186.738 µs | [185.231 µs, 187.568 µs] |
| lftj+simd+par | v=1000,e=99741,k4=977789 | 87.923 ms | [82.715 ms, 96.660 ms] |
| lftj+simd+par | v=1000,e=99741,k5=96211 | 88.334 ms | [83.946 ms, 93.545 ms] |
| lftj+simd+par | v=2000,e=79333,k4=1042 | 7.869 ms | [7.476 ms, 8.175 ms] |
| lftj+simd+par-window | v=1000,e=19936,k4=window-25% | 977.524 µs | [913.004 µs, 1.042 ms] |
| lftj+simd+par-window | v=1000,e=49535,k4=window-25% | 2.776 ms | [2.663 ms, 2.913 ms] |
| lftj+simd+par-window | v=1000,e=9913,k4=window-25% | 1.345 ms | [1.198 ms, 1.701 ms] |
| lftj+simd-window | v=1000,e=19936,k4=window-25% | 3.060 ms | [3.016 ms, 3.103 ms] |
| lftj+simd-window | v=1000,e=49535,k4=window-25% | 12.302 ms | [12.181 ms, 12.467 ms] |
| lftj+simd-window | v=1000,e=9913,k4=window-25% | 1.645 ms | [1.610 ms, 1.685 ms] |
| match-2hop | v=1000,b=2 | 816.504 µs | [800.824 µs, 834.788 µs] |
| match-2hop | v=10000,b=2 | 4.455 ms | [4.372 ms, 4.645 ms] |
| match-3hop | v=1000,b=2 | 1.006 ms | [1.002 ms, 1.011 ms] |
| match-3hop | v=10000,b=2 | 10.233 ms | [10.165 ms, 10.318 ms] |
| match-4hop | v=1000,b=2 | 1.726 ms | [1.719 ms, 1.737 ms] |
| match-4hop | v=10000,b=2 | 20.362 ms | [20.292 ms, 20.466 ms] |
| naive | v=1000,e=19936,c6=63267586 | 99.422 s | [97.215 s, 105.501 s] |
| naive | v=1000,e=19936,k4=0 | 10.173 ms | [9.709 ms, 10.822 ms] |
| naive | v=1000,e=19936,k4=64 | 2.687 ms | [2.683 ms, 2.690 ms] |
| naive | v=1000,e=19936,k5=0 | 2.742 ms | [2.740 ms, 2.748 ms] |
| naive | v=1000,e=19936,t=1298 | 3.102 ms | [2.979 ms, 3.199 ms] |
| naive | v=1000,e=19936,t=7811 | 1.764 ms | [1.762 ms, 1.766 ms] |
| naive | v=1000,e=49535,k4=14892 | 116.082 ms | [112.367 ms, 119.621 ms] |
| naive | v=1000,e=49535,k4=23 | 63.387 ms | [62.807 ms, 64.341 ms] |
| naive | v=1000,e=49535,k5=89 | 68.479 ms | [65.661 ms, 76.150 ms] |
| naive | v=1000,e=49535,t=121337 | 16.082 ms | [15.475 ms, 16.711 ms] |
| naive | v=1000,e=49535,t=20350 | 31.800 ms | [31.162 ms, 32.727 ms] |
| naive | v=1000,e=4969,c6=15464 | 81.845 ms | [78.800 ms, 98.034 ms] |
| naive | v=1000,e=4969,k4=0 | 283.846 µs | [277.237 µs, 289.826 µs] |
| naive | v=1000,e=4969,t=109 | 156.726 µs | [156.373 µs, 157.340 µs] |
| naive | v=1000,e=4969,t=18 | 232.859 µs | [227.231 µs, 235.787 µs] |
| naive | v=1000,e=9913,c6=926763 | 2.026 s | [2.024 s, 2.028 s] |
| naive | v=1000,e=9913,k4=0 | 1.478 ms | [1.468 ms, 1.497 ms] |
| naive | v=1000,e=9913,k4=1 | 586.449 µs | [585.755 µs, 587.987 µs] |
| naive | v=1000,e=9913,k5=0 | 878.915 µs | [855.821 µs, 932.649 µs] |
| naive | v=1000,e=99741,k4=977789 | 1.873 s | [1.844 s, 1.921 s] |
| naive | v=1000,e=99741,k5=96211 | 2.017 s | [1.962 s, 2.090 s] |
| naive | v=2000,e=39554,t=1303 | 5.987 ms | [5.760 ms, 6.312 ms] |
| naive | v=2000,e=39554,t=7768 | 4.296 ms | [4.165 ms, 4.714 ms] |
| naive | v=2000,e=79333,k4=1042 | 76.327 ms | [72.945 ms, 83.059 ms] |
| naive | v=500,e=2439,t=113 | 94.910 µs | [90.514 µs, 97.074 µs] |
| naive | v=500,e=2439,t=26 | 116.691 µs | [113.021 µs, 120.473 µs] |
| naive-window | v=1000,e=19936,k4=window-25% | 2.289 ms | [2.254 ms, 2.315 ms] |
| naive-window | v=1000,e=49535,k4=window-25% | 23.071 ms | [22.772 ms, 23.646 ms] |
| naive-window | v=1000,e=9913,k4=window-25% | 645.262 µs | [633.424 µs, 659.623 µs] |
| rebuild | v=1000,e=19936,k=1 | 5.456 ms | [5.261 ms, 5.610 ms] |
| rebuild | v=1000,e=19936,k=16 | 87.455 ms | [85.836 ms, 89.600 ms] |
| rebuild | v=1000,e=19936,k=4 | 23.477 ms | [22.589 ms, 23.953 ms] |
| rebuild | v=1000,e=19936,k=64 | 361.239 ms | [353.054 ms, 373.325 ms] |
| rebuild | v=1000,e=49535,k=1 | 19.215 ms | [18.758 ms, 19.864 ms] |
| rebuild | v=1000,e=49535,k=16 | 319.939 ms | [315.517 ms, 327.857 ms] |
| rebuild | v=1000,e=49535,k=4 | 78.245 ms | [76.869 ms, 79.657 ms] |
| rebuild | v=1000,e=49535,k=64 | 1.266 s | [1.255 s, 1.284 s] |
| rebuild-window | v=1000,e=19936,k=1 | 5.454 ms | [5.247 ms, 5.618 ms] |
| rebuild-window | v=1000,e=19936,k=16 | 19.644 ms | [19.014 ms, 20.263 ms] |
| rebuild-window | v=1000,e=19936,k=4 | 8.461 ms | [8.212 ms, 9.079 ms] |
| rebuild-window | v=1000,e=19936,k=64 | 76.630 ms | [75.972 ms, 77.488 ms] |
| rebuild-window | v=1000,e=49535,k=1 | 23.194 ms | [20.767 ms, 24.078 ms] |
| rebuild-window | v=1000,e=49535,k=16 | 49.635 ms | [48.332 ms, 52.830 ms] |
| rebuild-window | v=1000,e=49535,k=4 | 25.706 ms | [24.995 ms, 26.284 ms] |
| rebuild-window | v=1000,e=49535,k=64 | 172.076 ms | [160.244 ms, 179.953 ms] |
| score-path | 1 | 77 ns | [76 ns, 78 ns] |
| score-path | 2 | 214 ns | [201 ns, 244 ns] |
| score-path | 3 | 288 ns | [287 ns, 289 ns] |
| score-path | 4 | 395 ns | [394 ns, 396 ns] |
| shared | v=1000,e=19936,k=1 | 5.686 ms | [5.600 ms, 5.840 ms] |
| shared | v=1000,e=19936,k=16 | 78.903 ms | [77.451 ms, 80.413 ms] |
| shared | v=1000,e=19936,k=4 | 23.174 ms | [22.673 ms, 23.612 ms] |
| shared | v=1000,e=19936,k=64 | 319.842 ms | [315.257 ms, 323.553 ms] |
| shared | v=1000,e=49535,k=1 | 19.680 ms | [19.319 ms, 20.153 ms] |
| shared | v=1000,e=49535,k=16 | 310.150 ms | [300.813 ms, 326.407 ms] |
| shared | v=1000,e=49535,k=4 | 75.571 ms | [74.003 ms, 79.761 ms] |
| shared | v=1000,e=49535,k=64 | 1.235 s | [1.217 s, 1.261 s] |
| shared-window | v=1000,e=19936,k=1 | 5.952 ms | [5.775 ms, 6.608 ms] |
| shared-window | v=1000,e=19936,k=16 | 11.386 ms | [11.135 ms, 11.785 ms] |
| shared-window | v=1000,e=19936,k=4 | 6.995 ms | [6.828 ms, 7.170 ms] |
| shared-window | v=1000,e=19936,k=64 | 32.879 ms | [31.350 ms, 34.168 ms] |
| shared-window | v=1000,e=49535,k=1 | 22.108 ms | [21.095 ms, 22.747 ms] |
| shared-window | v=1000,e=49535,k=16 | 34.470 ms | [33.697 ms, 35.892 ms] |
| shared-window | v=1000,e=49535,k=4 | 23.197 ms | [22.682 ms, 23.511 ms] |
| shared-window | v=1000,e=49535,k=64 | 85.365 ms | [83.717 ms, 90.526 ms] |
| user-auth-ip | 1000 | 97.708 µs | [97.260 µs, 98.359 µs] |
| user-auth-ip | 10000 | 870.346 µs | [867.479 µs, 873.603 µs] |
| user-auth-ip | 100000 | 13.349 ms | [13.150 ms, 13.561 ms] |

## Suites expected

- `hunt_latency` — matcher wall-time for 1-hop spray across |V| ∈ {1K, 10K, 100K}.
- `dedup_throughput` — `score_and_paginate_paths` on redundant path sets.
- `ingest_throughput` — `SysmonJsonParser.parse()` on 1K / 10K / 50K NDJSON events.
- `matching_hops` — `search_temporal_pattern` for 2/3/4-hop patterns.
- `scoring_path` — `AnomalyScorer.score_path` over paths of length 1..4.

> Missing rows indicate that bench was not run on this host;
> re-run `cargo bench` to populate.
