use criterion::{criterion_group, criterion_main, Criterion};
use rust_sphincs::lib::helpers::random_generator::{RandomGeneratorSha256, Address, RandomGeneratorTrait, InnerKeyRole};

fn bench_sequential(c: &mut Criterion) {
    let mut generator = RandomGeneratorSha256::new([1;32]);

    c.bench_function("get_10000_keys_sequantial", |b| {
        b.iter(|| generator.get_keys::<10_000>(&Address { level: 2, position: 1000 }, InnerKeyRole::MessageKey));
    });
}

criterion_group!(benches, bench_sequential);
criterion_main!(benches);
