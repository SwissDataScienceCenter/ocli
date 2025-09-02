use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use ocli::{Config, finish_device_code_flow, start_device_code_flow};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// Adds files to myapp
    #[command(about = "get a token from an oidc endpoint")]
    Token(Token),
    #[command(
        about = "get config file from URL, use it for login and update the access token in local config files"
    )]
    Login(Login),
}

#[derive(Args)]
struct Token {
    #[arg(index = 1, help = "OIDC issue url")]
    url: String,
    #[arg(index = 2, help = "OIDC client_id")]
    client_id: String,
}

#[derive(Args)]
struct Login {
    #[arg(index = 1, help = "url to fetch config from")]
    url: String,
    #[arg(short, long, help = "whether to ask for confirmation or not")]
    force: bool,
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Token(args) => {
            // just do device code flow if we have a client id and print the token
            let token = do_device_flow(args.url.clone(), args.client_id.clone())
                .expect("couldn't get token from endpoint");
            println!("Access Token: \n{}", token.access_token());
            if let Some(refresh_token) = token.refresh_token() {
                println!("Refresh Token: \n{}", refresh_token);
            }
        }
        Commands::Login(login) => {
            let config = Config::download(login.url.clone()).expect("couldn't load config file");
            let token = do_device_flow(config.url.clone(), config.client_id.clone())
                .expect("couldn't get token from endpoint");
            if login.force {
                let (applied, skipped) = config.apply(token).expect("couldn't update config files");
                if !skipped.is_empty() {
                    println!(
                        "Skipped these rules as they did not apply:\n\t{}",
                        skipped.join("\n\t")
                    )
                }
                if !applied.is_empty() {
                    println!(
                        "Applied these rules and updated files:\n\t{}",
                        applied.join("\n\t")
                    )
                }
                return;
            }
            // verify files to be updated with user
            println!(
                "Will update the following files:\n\t{}\nContinue?(Y/n)",
                config
                    .affected_paths()
                    .expect("could not get affected paths")
                    .iter()
                    .map(|p| p.to_str().unwrap())
                    .collect::<Vec<&str>>()
                    .join("\n\t")
            );
            let mut input = String::new();
            match std::io::stdin().read_line(&mut input) {
                Ok(_) => {
                    if input.trim().is_empty() || input.trim() == "Y" || input.trim() == "y" {
                        let (applied, skipped) =
                            config.apply(token).expect("couldn't update config files");
                        if !skipped.is_empty() {
                            println!(
                                "Skipped these rules as they did not apply:\n\t{}",
                                skipped.join("\n\t")
                            )
                        }
                        if !applied.is_empty() {
                            println!(
                                "Applied these rules and updated files:\n\t{}",
                                applied.join("\n\t")
                            )
                        }
                    }
                }
                Err(error) => println!("error:{error}"),
            }
        }
    }
}

fn do_device_flow(url: String, client_id: String) -> Result<ocli::OIDCTokenset> {
    let data = start_device_code_flow(url.clone(), client_id.clone())
        .expect("device code flow not successful");
    println!(
        "Please visit {} and authorize this application.",
        data.verify_url_full
    );
    open::that(data.verify_url_full.clone())
        .or_else(|_| {
            println!(
                "Couldn't open browser, please navigate to {}",
                data.verify_url_full
            );
            std::io::Result::Ok(())
        })
        .unwrap();

    finish_device_code_flow(data)
}
