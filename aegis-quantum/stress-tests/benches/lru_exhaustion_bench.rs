use criterion::{black_box, criterion_group, criterion_main, Criterion};

use aegis_quantum_stress_tests::simulate_lru_saturation;

fn bench_lru_map_pressure(c: &mut Criterion) {
    let mut group = c.benchmark_group("aegis_kernel_lru_pressure");
    group.sample_size(20);
    group.bench_function("65536_entries_2x_saturation", |b| {
        b.iter(|| black_box(simulate_lru_saturation(black_box(65_536), black_box(2))))
    });
    group.finish();
}

criterion_group!(benches, bench_lru_map_pressure);
criterion_main!(benches);
