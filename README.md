# BLS Signatures with Arbitrum Stylus

This repository contains example code for a smart contract written in Rust that can verify [BLS signatures](https://www.cryptologie.net/article/472/what-is-the-bls-signature-scheme/) for [Arbitrum Stylus](https://arbitrum.io/stylus). Because it exposes a Solidity ABI, it can be called normally by other Solidity smart contracts.

**WARNING: NONE OF THIS CODE IS SAFE FOR PRODUCTION. IT IS MERELY FOR DEMONSTRATION PURPOSES. DO NOT USE IN PROD!**

The code uses the bls12_381 crate, which is not audited for safety and not meant for production uses. This is just a demonstration.

```js
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface BLSVerifier {
    function verifyBlsSignature(bytes calldata data) external view;
}
```

## Using

The contract takes in raw bytes where the first 96 are a BLS signature, the next 48 are a BLS public key, and the remaining bytes are the message that was signed. If no error is returned, the signature verifies.

An already deployed version of this contract exists at address: `0xd71aD5e7f4046A89f57a5B6FfefD56097fB0Ae04` on the Stylus testnet.

## Deploying

Install Rust. Then, install [cargo-stylus](https://github.com/OffchainLabs/cargo-stylus) with

```
cargo install cargo-stylus
```

Then, build with nightly:

```
cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --config "profile.release.opt-level='z'" --release
```

To deploy, you'll need testnet ETH on the Stylus testnet. See our quickstart [here](https://docs.arbitrum.io/stylus/stylus-quickstart).

Here's how to deploy:

```bash
cargo stylus deploy \
  --private-key=<PRIV_KEY_HEX_STRING> \
  --wasm-file-path=./target/wasm32-unknown-unknown/release/bls-stylus-example.wasm
```

Once this is successful, you can interact with your program as you would with any Ethereum smart contract.

The Solidity ABI can be exported using `cargo stylus export-abi`

```js
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface BLSVerifier {
    function verifyBlsSignature(bytes calldata data) external view;
}
```

## Calling Your Program

This template includes an example of how to call and transact with your program in Rust using [ethers-rs](https://github.com/gakonst/ethers-rs) under the `examples/bls.rs`. However, your programs are also Ethereum ABI equivalent if using the Stylus SDK. **They can be called and transacted with using any other Ethereum tooling.**

```rs
abigen!(
    BLSVerifier,
    r#"[
        function verifyBlsSignature(bytes calldata data) external view;
    ]"#
);
```

To run it, set the following env vars:

```
STYLUS_PROGRAM_ADDRESS=<the onchain address of your deployed program>
RPC_URL=https://stylus-testnet.arbitrum.io/rpc
```

An already deployed version of this contract exists at address: `0xd71aD5e7f4046A89f57a5B6FfefD56097fB0Ae04` on the Stylus testnet.

Next, run:

```
cargo run --example bls --target=<YOUR_ARCHITECTURE>
```

Where you can find `YOUR_ARCHITECTURE` by running `rustc -vV | grep host`. For M1 Apple computers, for example, this is `aarch64-apple-darwin` and for most Linux x86 it is `x86_64-unknown-linux-gnu`
