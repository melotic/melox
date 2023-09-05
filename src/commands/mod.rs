pub mod bin;

fn id_to_b58(x: u64) -> String {
    bs58::encode(x.to_be_bytes()).into_string()
}
