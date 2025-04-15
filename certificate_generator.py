import subprocess
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

# Initialize rich console for styled output
console = Console()

# Supported ECC curves
ECC_CURVES = {
    "1": "prime256v1",
    "2": "secp384r1",
    "3": "secp521r1",
}

# Supported RSA key sizes
RSA_SIZES = {
    "1": "2048",
    "2": "4096",
}


def print_logo():
    """Display the tool's logo using a styled panel."""
    console.print(Panel.fit(
        "[bold blue]Cert Gen[/bold blue]",
        title="[green]SSL/TLS Certificate Generator[/green]",
        subtitle="for CA or Self-Signed Certificates",
        border_style="cyan"
    ))


def run_command(command: str):
    """
    Execute a shell command and exit on failure.

    Args:
        command (str): The command to be executed.
    """
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError:
        console.print("[red]Error: Command failed to execute.[/red]")
        exit(1)


def get_certificate_mode():
    """
    Prompt the user to choose certificate generation mode.

    Returns:
        str: The selected option ("1" for CSR, "2" for self-signed).
    """
    console.print("Select certificate type:")
    console.print("1. Certificate Signing Request for CA")
    console.print("2. Self-Signed Certificate")
    choice = input("Enter your choice [1-2]: ").strip()
    return choice


def get_key_type():
    """
    Prompt the user to choose the key type and parameters.

    Returns:
        Tuple[str, str]: The key type and its corresponding size or curve.
    """
    console.print("Select key type:")
    console.print("1. RSA")
    console.print("2. ECC (Elliptic Curve)")
    choice = input("Enter your choice [1-2]: ").strip()

    if choice == "1":
        for k, v in RSA_SIZES.items():
            console.print(f"{k}. RSA {v} bits")
        rsa_choice = input("Choose RSA key size: ").strip()
        return "RSA", RSA_SIZES.get(rsa_choice, "2048")

    elif choice == "2":
        for k, v in ECC_CURVES.items():
            console.print(f"{k}. Curve {v}")
        ecc_choice = input("Choose ECC curve: ").strip()
        return "ECC", ECC_CURVES.get(ecc_choice, "prime256v1")

    else:
        console.print("[red]Invalid key type.[/red]")
        exit(1)


def get_certificate_subject():
    """
    Prompt the user to enter the certificate subject fields.

    Returns:
        Tuple[str, str]: The formatted subject string and domain (CN).
    """
    domain = input("Common Name (e.g. www.example.com): ").strip()
    C = input("Country Code (e.g. US): ").strip()
    ST = input("State or Province (e.g. California): ").strip()
    L = input("City or Locality (e.g. San Francisco): ").strip()
    O = input("Organization Name (e.g. Example Corp): ").strip()
    OU = input("Organizational Unit (e.g. IT Department): ").strip()
    return f"/C={C}/ST={ST}/L={L}/O={O}/OU={OU}/CN={domain}", domain


def get_san_extension():
    """
    Prompt the user to optionally add SAN (Subject Alternative Names).

    Returns:
        str: The formatted SAN extension string for OpenSSL or an empty string.
    """
    add_san = input("Do you want to add SANs (Subject Alternative Names)? [y/N]: ").strip().lower()
    if add_san == "y":
        san_entries = []
        count = 1
        while True:
            entry = input(f"Enter DNS.{count} (or press Enter to finish): ").strip()
            if not entry:
                break
            san_entries.append(f"DNS:{entry}")
            count += 1
        if san_entries:
            san_string = ",".join(san_entries)
            return f'-addext "subjectAltName = {san_string}"'
    return ""


def create_output_directory():
    """
    Ask the user for an output directory and create it.

    Returns:
        Path: The created directory path.
    """
    folder = input("Enter directory name to store certificate files: ").strip()
    path = Path(folder)
    path.mkdir(parents=True, exist_ok=True)
    return path


def generate_rsa_key(path: Path, size: str, filename: str):
    """
    Generate an RSA private key.

    Args:
        path (Path): Output directory path.
        size (str): RSA key size.
        filename (str): Base name for the output file.
    """
    run_command(f"openssl genrsa -out {path}/{filename}.key {size}")


def generate_ecc_key(path: Path, curve: str, filename: str):
    """
    Generate an ECC private key.

    Args:
        path (Path): Output directory path.
        curve (str): ECC curve name.
        filename (str): Base name for the output file.
    """
    run_command(f"openssl ecparam -name {curve} -genkey -noout -outform PEM -out {path}/{filename}.key")


def generate_csr(path: Path, subj: str, filename: str, san_option: str):
    """
    Generate a Certificate Signing Request (CSR).

    Args:
        path (Path): Output directory path.
        subj (str): Subject string.
        filename (str): Base name for the CSR file.
        san_option (str): Optional SAN extension.
    """
    command = f"openssl req -new -key {path}/{filename}.key -out {path}/{filename}.csr -subj \"{subj}\""
    if san_option:
        command += f" {san_option}"
    run_command(command)


def generate_self_signed_cert(path: Path, subj: str, filename: str):
    """
    Generate a self-signed certificate.

    Args:
        path (Path): Output directory path.
        subj (str): Subject string.
        filename (str): Base name for the certificate file.
    """
    run_command(f"openssl req -x509 -new -nodes -key {path}/{filename}.key -sha256 -days 365 -out {path}/{filename}.crt -subj \"{subj}\"")


def validate_csr(path: Path, filename: str):
    """
    Display and validate the CSR contents.

    Args:
        path (Path): Output directory path.
        filename (str): Base name of the CSR file.
    """
    run_command(f"openssl req -text -noout -verify -in {path}/{filename}.csr")


def validate_self_signed_cert(path: Path, filename: str):
    """
    Display and validate the self-signed certificate.

    Args:
        path (Path): Output directory path.
        filename (str): Base name of the certificate file.
    """
    run_command(f"openssl x509 -in {path}/{filename}.crt -text -noout")


def main():
    """Main function that orchestrates the certificate generation process."""
    print_logo()
    mode = get_certificate_mode()
    key_type, key_param = get_key_type()
    subj, domain = get_certificate_subject()
    san_option = get_san_extension()
    path = create_output_directory()

    # Sanitize filename to avoid issues with wildcard or dots
    sanitized_filename = domain.replace("*", "wildcard").replace(".", "_")

    # Generate private key based on selected type
    if key_type == "RSA":
        generate_rsa_key(path, key_param, sanitized_filename)
    else:
        generate_ecc_key(path, key_param, sanitized_filename)

    # Generate CSR or self-signed certificate
    if mode == "1":  # CSR for CA
        generate_csr(path, subj, sanitized_filename, san_option)
        validate_csr(path, sanitized_filename)
    elif mode == "2":  # Self-signed certificate
        generate_self_signed_cert(path, subj, sanitized_filename)
        validate_self_signed_cert(path, sanitized_filename)
    else:
        console.print("[red]Invalid mode selected.[/red]")
        exit(1)

    # Output the directory path where files were saved
    console.print("\nCertificate files saved in:", style="bold green")
    console.print(str(path.resolve()))


if __name__ == "__main__":
    main()