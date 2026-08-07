mod config;

fn main() {
    println!("{}", config::config_path("/tmp"));
}
