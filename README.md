# Stork Oracle Multi-Account Bot

Automated bot to run Stork Oracle validations on multiple accounts simultaneously with proxy support.

## Features

- ✅ Multi-account support with separate configurations
- ✅ Automatic proxy rotation for each account
- ✅ Automatic token refresh
- ✅ Customizable validation intervals per account
- ✅ Adjustable worker count per account
- ✅ Real-time monitoring for each account
- ✅ Robust error handling

## Requirements

- Node.js (v14.0.0 or newer)
- npm or yarn

## Directory Structure
```bash
stork-oracle-bot/
  ├── index.js              # Main script
  ├── proxies.txt           # List of proxies
  ├── accounts/             # Directory for account configurations
  │   ├── account1.json     # Configuration for account 1
  │   ├── account2.json     # Configuration for account 2
  │   ├── ...
  │   └── account1_tokens.json  # Tokens for account 1 (created automatically)
```
## Installation

1. Clone this repository:
```bash
git clone https://github.com/chichiops/stork-oracle-bot.git
cd stork-oracle-bot
```
2. Install dependencies:
```bash
npm install
```
## Account Configuration
For each account, create a JSON file in the `account.json` directory with the following format:
```bash
{
  "username": "your_email@example.com",
  "password": "your_password",
  "intervalSeconds": 10,
  "maxWorkers": 5
}
```
The filename is arbitrary (e.g., account1.json, myaccount.json, etc.) and will be detected automatically.

## Proxy Configuration (Optional)
Create a `proxies.txt` file in the root directory with one proxy per line:
```bash
http://user:pass@host:port
socks5://host:port
http://host:port
```
## Run the bot:
```bash
node index.js
```
