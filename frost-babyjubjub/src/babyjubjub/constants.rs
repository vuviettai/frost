// https://zeropool.network/docs/privacy-engine/implementation/elliptic-curve-cryptography/
// https://github.com/zk-kit/zk-kit/blob/main/packages/baby-jubjub/src/baby-jubjub.ts
// https://github.com/0xPolygonID/tutorial-examples/blob/main/issuer-protocol/main.go#L21
// https://docs.iden3.io/publications/pdfs/Baby-Jubjub.pdf

// p= 21888242871839275222246405745257275088548364400416034343698204186575808495617
// p = 2^254 - 2^32 - 977

// a*x^2 + y^2 = 1 + d*x^2*y^2
// Coefficient a: 168700
// Coefficient d: 168696
// The curve finite field modulus: q= 21888242871839275222246405745257275088548364400416034343698204186575808495617
// The curve order: 21888242871839275222246405745257275088614511777268538073601725287587578984328
// Subgroup cofactor: 8
// Subgroup order: r = 2736030358979909402780800718157159386076813972158567259200215660948447373041
// Generator point
// (x,y): 15432774951723927157031250336277790668279068029556328898354949310072202318295, 1094793399012674419577823790376044935246658671901627841542961578327961423020

/// r = 2736030358979909402780800718157159386076813972158567259200215660948447373041
/// 0x060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1
pub const MODULUS: [u64; 4] = [
    0x6772_97dc_3921_26f1,
    0xab3e_edb8_3920_ee0a,
    0x370a_08b6_d030_2b0b,
    0x060c_89ce_5c26_3405,
];

// The number of bits needed to represent the modulus.
pub const MODULUS_BITS: u32 = 251;

/// 2^-1
/// 10944121435919637611123202872628637544274182200208017171849102093287904247809.
/// 0x183227397098D014DC2822DB40C0AC2E9419F4243CDCB848A1F0FAC9F8000001
/// Since p ≡ 3 (mod 4), this can be calculated simply as:
/// 2⁻¹ ≡ (p + 1)/2 (mod p)
pub const TWO_INV: [u64; 4] = [
    0x1832_2739_7098_d014,
    0xdc28_22db_40c0_ac2e,
    0x9419_f424_3cdc_b848,
    0xa1f0_fac9_f800_0001,
];

// GENERATOR = 6 (multiplicative generator of r-1 order, that is also quadratic nonresidue)
pub const GENERATOR: [u64; 4] = [
    0x720b_1b19_d49e_a8f1,
    0xbf4a_a361_01f1_3a58,
    0x5fa8_cc96_8193_ccbb,
    0x0e70_cbdc_7dcc_f3ac,
];

// 2^S * t = MODULUS - 1 with t odd
pub const S: u32 = 3;

// 2^S root of unity computed by GENERATOR^t
const ROOT_OF_UNITY: Fr = Fr([
    0xaa9f_02ab_1d61_24de,
    0xb352_4a64_6611_2932,
    0x7342_2612_15ac_260b,
    0x04d6_b87b_1da2_59e2,
]);

/// ROOT_OF_UNITY^-1 (which is equal to ROOT_OF_UNITY because S = 1).
const ROOT_OF_UNITY_INV: Fr = ROOT_OF_UNITY;

/// GENERATOR^{2^s} where t * 2^s + 1 = q with t odd.
/// In other words, this is a t root of unity.
const DELTA: Fr = Fr([
    0x994f_5ac0_c8e4_1613,
    0x3bb7_3163_0bbf_0b84,
    0x1df0_a482_0371_a563,
    0x0e30_3e96_f8cb_47bd,
]);

/// INV = -(r^{-1} mod 2^64) mod 2^64
const INV: u64 = 0x1ba3_a358_ef78_8ef9;

/// R = 2^256 mod r
/// 115792089237316195423570985008687907853269984665640564039457584007913129639936
const R: Fr = Fr([
    0x25f8_0bb3_b996_07d9,
    0xf315_d62f_66b6_e750,
    0x9325_14ee_eb88_14f4,
    0x09a6_fc6f_4791_55c6,
]);

/// R^2 = 2^512 mod r
const R2: Fr = Fr([
    0x6771_9aa4_95e5_7731,
    0x51b0_cef0_9ce3_fc26,
    0x69da_b7fa_c026_e9a5,
    0x04f6_547b_8d12_7688,
]);

/// R^3 = 2^768 mod r
const R3: Fr = Fr([
    0xe0d6_c656_3d83_0544,
    0x323e_3883_598d_0f85,
    0xf0fe_a300_4c2e_2ba8,
    0x0587_4f84_9467_37ec,
]);
