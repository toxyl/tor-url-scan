# Tor URLScan Client

A simple Go web app that communicates with the [urlscan.io](https://urlscan.io/) API over Tor. Submit URLs via the web interface and view detailed scan reports.

> **Note:** Only the communication with urlscan.io is routed through Tor. How the URL is scanned is determined by urlscan.io.

## Requirements

- **Tor:** Install and run [Tor](https://www.torproject.org/). The app uses Tor's SOCKS5 proxy (default: `127.0.0.1:9050`).
- **URLScan.io API Key:** Obtain one from [urlscan.io](https://urlscan.io/).

## Quick Start

1. **Clone the Repository:**

   ```sh
   git clone https://github.com/toxyl/tor-url-scan.git
   cd tor-url-scan
   ```

2. **Build the Application:**

   ```sh
   go mod tidy
   go build -o tor-url-scan
   ```

3. **Run and Configure:**

   On the first run, you'll be prompted to enter:
   
   - Your Tor SOCKS5 proxy address (default is `127.0.0.1:9050`)
   - Your urlscan.io API key

   This information is saved to `~/.urlscan_client.yaml`.

   Start the app:

   ```sh
   ./tor-url-scan
   ```

4. **Access the Web Interface:**

   Open your browser and navigate to [http://localhost:3000](http://localhost:3000) to submit a URL scan.

Happy scanning!