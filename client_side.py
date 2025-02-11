import asyncio
import gzip
import hashlib
import ssl
import os

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

async def compress_file(file_path):
    """
    Compress the given file using gzip.

    Args:
        file_path (str): Path to the file to be compressed.

    Returns:
        str: Path to the compressed file.
    """
    compressed_file_path = f"{file_path}.gz"
    with open(file_path, 'rb') as f_in, gzip.open(compressed_file_path, 'wb') as f_out:
        while chunk := f_in.read(1024):
            f_out.write(chunk)
    return compressed_file_path

async def send_file_header(writer, file_name, file_hash):
    """
    Send the file header (name and hash) to the server.

    Args:
        writer (StreamWriter): The writer object to send data to the server.
        file_name (str): The name of the file being sent.
        file_hash (str): The SHA-256 hash of the file.
    """
    writer.write(len(file_name.encode()).to_bytes(4, byteorder='big'))
    writer.write(file_name.encode())
    writer.write(file_hash.encode())
    writer.write(b'\n')  # Add newline to separate hash from data

async def send_file_data(writer, file_path):
    """
    Send the file data in chunks to the server.

    Args:
        writer (StreamWriter): The writer object to send data to the server.
        file_path (str): Path to the file being sent.
    """
    with open(file_path, 'rb') as file:
        while chunk := file.read(1024):
            writer.write(chunk)
            await writer.drain()

async def send_multiple_files(files, server_ip, server_port):
    """
    Send multiple files and their hashes to the server securely over SSL.

    Args:
        files (list of str): List of file paths to be sent.
        server_ip (str): IP address of the server.
        server_port (int): Port of the server.
    """
    # Set up SSL context for secure communication
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False  # Disable hostname verification
    context.verify_mode = ssl.CERT_NONE  # Disable certificate verification

    # Connect to the server using SSL
    reader, writer = await asyncio.open_connection(server_ip, server_port, ssl=context)

    for file_path in files:
        if not os.path.exists(file_path):
            print(f"Error: The file {file_path} does not exist.")
            continue

        try:
            # Compress the file
            compressed_file_path = await compress_file(file_path)
            print(f"File {file_path} compressed to {compressed_file_path}")

            # Compute the SHA-256 hash of the compressed file
            file_hash = await compute_sha256(compressed_file_path)
            print(f"SHA-256 hash of the compressed file: {file_hash}")

            file_name = os.path.basename(compressed_file_path)
            print(f"Sending file: {file_name}")

            # Send file header (name and hash)
            await send_file_header(writer, file_name, file_hash)

            # Send the file content
            await send_file_data(writer, compressed_file_path)

            print(f"File {file_name} sent successfully with SHA-256 hash.")

        except Exception as e:
            print(f"Error occurred while sending {file_path}: {e}")

    writer.close()
    await writer.wait_closed()

async def get_user_input():
    """
    Prompt the user for file paths, server IP, and server port.

    Returns:
        tuple: (list of str) files, (str) server_ip, (int) server_port
    """
    files_input = input("Enter the paths of files to send, separated by commas: ").strip()

    # Check if input is a valid string
    if isinstance(files_input, str):
        # Remove quotes and split the input into file paths
        files = [os.path.normpath(file.strip('"').strip()) for file in files_input.split(',')]
    else:
        print("Invalid input! Please enter the file paths as a string.")
        return None, None, None

    server_ip = input("Enter the server IP address: ").strip()
    server_port = int(input("Enter the server port (1024-65535): ").strip())

    # Validate the server port
    if not (1024 <= server_port <= 65535):
        print("Port must be between 1024 and 65535.")
        return None, None, None

    return files, server_ip, server_port

async def main():
    """
    Main entry point for the client-side file transfer application.
    Prompts for user input and sends files to the server with error handling.
    """
    while True:
        try:
            files, server_ip, server_port = await get_user_input()

            if not files or not server_ip or not server_port:
                print("Error: Invalid input. Please try again.")
                continue  # Restart the loop and prompt again

            await send_multiple_files(files, server_ip, server_port)

            # Ask if the user wants to send more files
            while True:
                send_more = input("Do you want to send more files? (yes/no): ").strip().lower()
                if send_more in ["yes", "no"]:
                    break
                print("Invalid input. Please enter 'yes' or 'no'.")

            if send_more == "no":
                print("Exiting...")
                break  # Exit the while loop and allow the program to end naturally

        except KeyboardInterrupt:
            print("\nUser interrupted the program. Exiting safely...")
            break  # Exit the loop cleanly on Ctrl+C

        except Exception as e:
            print(f"Unexpected error: {e}. Restarting input process...")
            continue  # Restart the loop in case of unexpected errors



if __name__ == "__main__":
    asyncio.run(main())
