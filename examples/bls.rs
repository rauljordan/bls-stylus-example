use ethers::{
    prelude::abigen,
    providers::{Http, Provider},
    types::Address,
};
use eyre::eyre;
use std::sync::Arc;

// RPC URL FOR A STYLUS CHAIN ENDPOINT.
const ENV_RPC_URL: &str = "RPC_URL";
// DEPLOYED PROGRAM ADDRESS FOR STYLUS-HELLO-WORLD.
const ENV_PROGRAM_ADDRESS: &str = "STYLUS_PROGRAM_ADDRESS";

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let rpc_url =
        std::env::var(ENV_RPC_URL).map_err(|_| eyre!("No {} env var set", ENV_RPC_URL))?;
    let program_address = std::env::var(ENV_PROGRAM_ADDRESS)
        .map_err(|_| eyre!("No {} env var set", ENV_PROGRAM_ADDRESS))?;
    abigen!(
        BLSVerifier,
        r#"[
            function verifyBlsSignature(bytes calldata data) external view;
        ]"#
    );

    let provider = Provider::<Http>::try_from(rpc_url)?;
    let provider = Arc::new(provider);
    let address: Address = program_address.parse()?;

    let verifier = BLSVerifier::new(address, provider.clone());
    let mut data = vec![];
    let public_key = hex::decode("87033f48fd8f327ff5d164e85af31433c6a8c73fc5a65bad5d472127205c73c5168a45e862f5af6d0da5676df45d0a5f1293a530d5498f812a34a280f6bef869e4ca9b7c275554456d8770733d72ac4006777382fa541873fe002adb12184268").unwrap();
    let signature = hex::decode("98733cc2b312d5787cd4dba6ea0e19a1f1850b9e8c6d5112f12e12db8e7413a4ecb4096c23730566c67d9b2694e4e179").unwrap();
    let message = hex::decode("e751fdb69185002b13c8d2954c7d0c39546402ecdde9c2a9a2c624293535a5ca2f560a582f705580448fbe1ccdc0e86af3ba4c487a7f73bc9c312556").unwrap();
    dbg!(public_key.len());
    dbg!(signature.len());
    dbg!(message.len());

    data.extend(public_key);
    data.extend(signature);
    data.extend(message);

    let result = verifier.verify_bls_signature(data.into()).call().await;
    println!("Got result {:?}", result);

    Ok(())
}
