
# NetSpect 🌐✨

**NetSpect** is a beautiful and user-friendly command-line networking analysis tool built with Python.
It aims to provide essential networking utilities with clear, colorful, and well-structured output.

## Features

*   **Ping**: Check host reachability with detailed statistics.
*   **Port Scan**: Scan for open TCP ports on a target host.
*   **DNS Lookup**: Resolve hostnames to IP addresses and query various DNS record types (A, AAAA, MX, NS).
*   **Interface Info**: Display information about local network interfaces.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/hacksphere12/netspect.git
    cd netspect
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Make the tool executable (optional, for easier access):**
    You can install it as an editable package:
    ```bash
    pip install -e .
    ```
    Or create an alias, or add the `netspect` directory to your PATH.
    For now, you can run it directly:
    ```bash
    python -m netspect.cli --help
    ```

## Usage

NetSpect uses a command-line interface powered by Typer.

```bash
python -m netspect.cli [COMMAND] [OPTIONS]
