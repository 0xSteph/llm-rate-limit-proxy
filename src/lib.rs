pub mod config;

pub fn run() {
    println!("sluice v{}", env!("CARGO_PKG_VERSION"));
}
