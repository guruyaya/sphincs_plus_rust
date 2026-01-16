use criterion::{criterion_group, criterion_main, Criterion};
use rust_sphincs::lib::helpers::random_generator::{RandomGenerator64, Address, RandomGeneratorTrait};

fn bench_sequential(c: &mut Criterion) {
    let mut generator = RandomGenerator64::new([1;32]);

    c.bench_function("get_10000_keys_sequantial", |b| {
        b.iter(|| generator.get_keys(10_000, Address { level: 2, position: 1000 }));
    });
}

criterion_group!(benches, bench_sequential);
criterion_main!(benches);
