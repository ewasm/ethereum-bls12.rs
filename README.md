# ethereum-bls12.rs

This is an experiment to make [BLS12-381](https://blog.z.cash/new-snark-curve/) elliptic curve operations available on Ethereum as a precompiles.
Inspired from [ethereum-bn128.rs](https://github.com/ewasm/ethereum-bn128.rs).

The encoding used is the one suggested at page 66 of [the sapling spec](https://github.com/zcash/zips/blob/master/protocol/sapling.pdf), which differs [from the one used in Ethereum for bn128](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-197.md)
