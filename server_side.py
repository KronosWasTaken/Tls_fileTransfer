import asyncio
import hashlib
import os
import ssl
from functools import partial

global server_run


async def compute_sha256(file_path):
    """
    Compute the SHA-256 hash of the given file.

    Args:
        file_path (str): Path to the file for which to compute the hash.

    Returns:
        str: The SHA-256 hash of the file.
    """
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(1024):
            sha256.update(chunk)
    return sha256.hexdigest()


async def receive_file_header(reader):
    """
    Receive the file header (name and hash) from the client.

    Args:
        reader (StreamReader): The reader object to read data from the socket.

    Returns:
        tuple: (str) file_name, (str) file_hash
    """
    data = await reader.read(4)
    file_name_length = int.from_bytes(data, byteorder='big')

    file_name = await reader.read(file_name_length)
    file_name = file_name.decode()

    file_hash = await reader.read(64)  # SHA-256 hash length is 64 characters

    return file_name, file_hash.decode()


async def receive_file_data(reader, file_path):
    """
    Receive file data in chunks and save it to the specified file path.

    Args:
        reader (StreamReader): The reader object to read file data.
        file_path (str): Path where the received file will be saved.
    """
    with open(file_path, 'wb') as file:
        while True:
            data = await reader.read(1024)
            if not data:
                break
            file.write(data)


async def save_file(reader, server_directory):
    """
    Receive the file, save it to the server, and verify its hash.

    Args:
        reader (StreamReader): The reader object to read data from the client.
        server_directory (str): The directory on the server to save files.

    Returns:
        str: The name of the file saved.
    """
    file_name, expected_hash = await receive_file_header(reader)
    print(f"Receiving file: {file_name} with expected hash: {expected_hash}")

    # Ensure valid path (handle empty and invalid inputs)
    server_directory = os.path.normpath(server_directory)
    if not os.path.exists(server_directory):
        print(f"Error: The directory {server_directory} does not exist.")
        return

    # Ensure there's a valid directory to save the file
    file_path = os.path.join(server_directory, file_name)
    file_path = os.path.normpath(file_path)

    await receive_file_data(reader, file_path)

    # Compute hash of the received file
    file_hash = await compute_sha256(file_path)

    # Compare the hash of the received file with the expected hash
    if file_hash == expected_hash:
        print(f"File {file_name} received successfully and hash verified.")
    else:
        print(f"File hash mismatch! Expected: {expected_hash}, Received: {file_hash}")

    return file_name


async def handle_client(reader, writer, server_directory):
    """
    Handle client connections by receiving and saving files.

    Args:
        reader (StreamReader): The reader object to read data from the client.
        writer (StreamWriter): The writer object to send data to the client.
        server_directory (str): The directory to save the received files.
    """
    try:
        while True:
            file_name = await save_file(reader, server_directory)
            print(f"File {file_name} saved successfully.")



    except Exception as e:
        print(f"Error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def start_server(host, port, server_directory):
    """
    Start the secure file transfer server with SSL.

    Args:
        host (str): The host address (IP or hostname) for the server.
        port (int): The port on which the server listens for connections.
        server_directory (str): The directory to save the received files.
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

    server = await asyncio.start_server(
        partial(handle_client, server_directory=server_directory), host, port, ssl=context
    )

    addr = server.sockets[0].getsockname()
    print(f"Server started and listening on {addr}")

    async with server:
        await server.serve_forever()


async def get_server_input():
    """
    Prompt the user for the server's IP, port, and directory.

    Returns:
        tuple: (str) host, (int) port, (str) server_directory
    """
    host = input("Enter the server IP address: ").strip()
    port = int(input("Enter the server port (1024-65535): ").strip())

    if not (1024 <= port <= 65535):
        print("Port must be between 1024 and 65535.")
        return None, None

    server_directory = input("Enter the directory where files should be saved: ").strip()

    if not os.path.exists(server_directory):
        print(f"Error: The directory {server_directory} does not exist.")
        return None, None

    return host, port, server_directory


async def main():
    """
    Main entry point for the server-side file transfer application.
    Starts the server after getting user input.
    """
    global server_run
    host, port, server_directory = await get_server_input()

    if host and port and server_directory:
        # Start the server and let it handle the file transfers
        server_run = True
        if server_run:
            await start_server(host, port, server_directory)
        else:
            exit()


if __name__ == "__main__":
    asyncio.run(main())
