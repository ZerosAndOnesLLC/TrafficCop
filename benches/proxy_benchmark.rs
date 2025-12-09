use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn router_matching_benchmark(c: &mut Criterion) {
    // Router matching benchmarks will be added as implementation progresses
    c.bench_function("placeholder", |b| {
        b.iter(|| {
            black_box(1 + 1)
        })
    });
}

criterion_group!(benches, router_matching_benchmark);
criterion_main!(benches);
