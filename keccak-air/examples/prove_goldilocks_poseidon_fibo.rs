use std::fmt::Debug;

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, MdsMatrixGoldilocks};
use p3_keccak_air::{FibonacciAir, generate_trace_rows, NUM_FIBONACCI_COLS};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon::Poseidon;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand::{random, thread_rng};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};
use p3_matrix::dense::RowMajorMatrix;

fn main() -> Result<(), impl Debug> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Val, 2>;

    type Perm = Poseidon<Val, MdsMatrixGoldilocks, 8, 7>;
    let perm = Perm::new_from_rng(4, 22, MdsMatrixGoldilocks, &mut thread_rng());

    type MyHash = PaddingFreeSponge<Perm, 8, 4, 4>;
    let hash = MyHash::new(perm.clone());

    type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;
    let compress = MyCompress::new(perm.clone());

    type ValMmcs = FieldMerkleTreeMmcs<
        <Val as Field>::Packing,
        <Val as Field>::Packing,
        MyHash,
        MyCompress,
        4,
    >;
    let val_mmcs = ValMmcs::new(hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Dft = Radix2DitParallel;
    let dft = Dft {};

    type Challenger = DuplexChallenger<Val, Perm, 8, 4>;

    const NUM_FIBONACCI_ROWS: usize = 64;
    let mut values: Vec<Vec<u64>> = Vec::with_capacity(NUM_FIBONACCI_ROWS);
    values.push(vec![1, 1, 2]);
    for i in 1..NUM_FIBONACCI_ROWS {
        values.push(vec![
            values[i - 1][1],
            values[i - 1][2],
            values[i - 1][1] + values[i - 1][2],
        ]);
    }
    let trace = RowMajorMatrix {
        values: values
            .into_iter()
            .flatten()
            .map(|x| Val::from_canonical_u64(x))
            .collect::<Vec<_>>(),
        width: NUM_FIBONACCI_COLS,
    };

    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs::new(dft, val_mmcs, fri_config);

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs);

    let mut challenger = Challenger::new(perm.clone());
    let proof = prove(&config, &FibonacciAir {}, &mut challenger, trace, &vec![]);

    let mut challenger = Challenger::new(perm);
    verify(&config, &FibonacciAir {}, &mut challenger, &proof, &vec![])
}
