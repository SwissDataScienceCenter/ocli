# ocli

ocli is a generic OIDC applictation that allows you to get tokens and configure software with those tokens easily.

## Installation

### CLI (todo)

```bash
# curl -LO <todo> && chmod +x ocli && mv ocli /usr/local/bin/
```

### Python Client Library (todo)

```bash
$ pip install pyocli
```

## Usage

### CLI

Getting a token for an OIDC provider:

```bash
$ ocli token <url to oidc provider> <oidc client_id>
```
this will do an Oauth2 device code flow and print the returned access token on the CLI.

Getting a token using a ocli config file:

```bash
$ ocli token <url to ocli config file>
```
this will do an Oauth2 device code flow based on the details in the config file and print
the returned access token on the CLI.

Logging in and updating local configuration with the new token:

```bash
$ ocli login <url to ocli config file>
```
This will do a device code flow based on the config file and then update local configuration
based on the update rules in the config file.

### Python client library

Getting a token for an OIDC app:

```python
from pyocli import start_device_code_flow, finish_device_code_flow

oidc_issuer_url = "..."
oidc_client_id = "..."
data = start_device_code_flow(oidc_issuer_url, oidc_client_id)
print(f"Please navigate to {data.verify_url_full()} and log in")
token = finish_device_code_flow(data)
```

Logging in and updating the system based on a config file:

```python
from pyocli import Config

config_path = "..."
config = Config.load(config_path)
data = config.start_device_code_flow()
print(f"Please navigate to {data.verify_url_full()} and log in")
token = config.finish_device_code_flow(data)

result = config.apply(token)
print(result)
```
