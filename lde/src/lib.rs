//! This crate contains a framework for low-degree tests (LDTs).

#![no_std]

mod naive;

pub use naive::*;

extern crate alloc;

use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

pub trait TwoAdicSubgroupLDE<F, EF>
where
    F: Field,
    EF: ExtensionField<F> + TwoAdicField,
{
    /// The result type. Typically this will be `EF`, but it may also be a compressed encoding of
    /// the subspace of `EF` that may be produced by LDEs.
    type Res: Into<EF>;

    /// Given a batch of polynomials, each defined by `2^k` evaluations over the subgroup generated
    /// by `EF::primitive_root_of_unity(k)`, compute their evaluations over the subgroup generated
    /// by `EF::primitive_root_of_unity(k + added_bits)`.
    fn subgroup_lde_batch(
        &self,
        polys: RowMajorMatrix<F>,
        added_bits: usize,
    ) -> RowMajorMatrix<Self::Res>;
}

pub trait TwoAdicCosetLDE<F, EF>
where
    F: Field,
    EF: ExtensionField<F> + TwoAdicField,
{
    /// The result type. Typically this will be `EF`, but it may also be a compressed encoding of
    /// the subspace of `EF` that may be produced by LDEs.
    type Res: Into<EF>;

    fn shift(&self, lde_bits: usize) -> EF;

    /// Given a batch of polynomials, each defined by `2^k` evaluations over the subgroup generated
    /// by `EF::primitive_root_of_unity(k)`, compute their evaluations over the coset `shift H`,
    /// where `H` is the subgroup generated by `EF::primitive_root_of_unity(k + added_bits)`.
    fn coset_lde_batch(
        &self,
        polys: RowMajorMatrix<F>,
        added_bits: usize,
    ) -> RowMajorMatrix<Self::Res>;
}