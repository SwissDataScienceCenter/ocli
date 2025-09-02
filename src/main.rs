use clap::Parser;
use ocli::request_token;

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
    let token = request_token(args.url, args.client_id).expect("couldn't get token");
    println!("Token: {}", token);
}
