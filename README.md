# Secure File Transfer Over a Network Using TLS Protocol

## Overview
This project implements a **Secure File Transfer System** over a network using **TLS encryption** in Python. It ensures **confidentiality**, **integrity**, and **efficiency** in file transfers using:
- **TLS Encryption** (via Python's `ssl` library) for secure communication.
- **SHA-256 Hashing** for integrity verification.
- **Gzip Compression** for optimized file transfers.
- **Asynchronous Operations** for handling multiple transfers efficiently.

## Features
- **Encrypted communication** using TLS.
- **Integrity verification** through SHA-256 hash comparison.
- **Efficient transfers** with Gzip compression.
- **Concurrent file handling** with Python's `asyncio`.

## Project Structure
```
secure-file-transfer/
├── client.py        # Client-side implementation
├── server.py        # Server-side implementation
├── key.pem 
├── cert.pem        
```

## Installation
### Prerequisites
- Python 3.7+
- OpenSSL (for TLS encryption)

### Setup
1. **Clone the repository**
   ```sh
   git clone https://github.com/KronosWasTaken/Tls_fileTransfer.git
    cd Tls_fileTransfer
   ```
2. **Install dependencies**
   ```sh
   pip install asyncio gzip ssl
   ```
 3. **Generate SSL Certificates**

1. Open a terminal or command prompt and run the following command to generate a self-signed SSL certificate and a private key:

   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
   ```
   The command will generate two files:

    cert.pem: The public SSL certificate.
   
    key.pem: The private SSL key.

Place both cert.pem and key.pem files in the same directory as the client script to ensure SSL can be used correctly for file transfer.

## Usage
### Running the Server
1. Start the server:
   ```sh
   python server_side.py 
   ```
2. The server will listen for incoming file transfer requests.

### Running the Client
1. Run the client to send files:
   ```sh
   python client_side.py
   ```
2. The client compresses, encrypts, and transfers files securely.

## Security Features
- **TLS Encryption**: Prevents eavesdropping and MITM attacks.
- **SHA-256 Hashing**: Ensures file integrity after transmission.
- **Gzip Compression**: Reduces transfer time and bandwidth usage.
- **Asynchronous Execution**: Handles multiple transfers concurrently.



