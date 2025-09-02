use clap::Parser;
use ocli::device_code_flow;

#[derive(Parser, Debug)]
#[command(version, about, long_about=None)]
struct Args {
    #[arg(short, long)]
    url: String,
    #[arg(short, long)]
    client_id: String,
}
fn main() {
    let args = Args::parse();
    let token = device_code_flow(args.url, args.client_id).expect("couldn't get token");
    println!("Token: {}", token.access_token());
}
