use ethers::{
    middleware::SignerMiddleware,
    prelude::abigen,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{transaction::eip2718::TypedTransaction, Address, Eip1559TransactionRequest},
};
use eyre::eyre;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
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
    let address: Address = program_address.parse()?;
    let client = Arc::new(provider);
    let address: Address = program_address.parse()?;

    let verifier = BLSVerifier::new(address, client.clone());
    let mut data = vec![];

    let signature = hex::decode("a388ba9227c6f4d08954d017956b3dd947e5a18a9df064d137417afa8e8809e848af1ad8e47d887820e86a6a50ea0ba001fa422935358c7e0eec86077613406e69953688490437408d08a6995ec57dfccbba0c0f2ce42e8d18359ac0148fc915").unwrap();
    let pubkey = hex::decode("a5acc7f57b7df6ade2b7630e09a925b2ef10fb8c977aa1656b526db0d02b3998055c74f74fc79034678c352ddf531591").unwrap();
    let message = hex::decode("666f6f626172").unwrap();

    dbg!(pubkey.len());
    dbg!(signature.len());
    dbg!(message.len());

    data.extend(signature);
    data.extend(pubkey);
    data.extend(message);

    let resp = verifier.verify_bls_signature(data.into()).await?;
    dbg!(resp);

    Ok(())
}

fn read_secret_from_file(fpath: &str) -> eyre::Result<String> {
    let f = std::fs::File::open(fpath)?;
    let mut buf_reader = BufReader::new(f);
    let mut secret = String::new();
    buf_reader.read_line(&mut secret)?;
    Ok(secret.trim().to_string())
}
