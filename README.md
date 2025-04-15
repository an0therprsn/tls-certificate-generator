# TLS Certificate Generator  
**TLS Certificate Generator** is an interactive Python tool for generating SSL/TLS certificates using OpenSSL. It supports both **RSA** and **ECC (Elliptic Curve)** keys and can produce **Certificate Signing Requests (CSRs)** or **self-signed certificates**, all through a guided terminal interface.  
  
## Features  
- 🔑 Generate RSA or ECC private keys  
- 📝 Create Certificate Signing Requests (CSRs)  
- 📜 Generate self-signed certificates  
- 🌐 Add Subject Alternative Names (SAN)  
- 📂 Save all generated files in a custom directory  
  
## Requirements  
- Python 3.7+  
- OpenSSL installed on the system  
  
## Installation  
**1. Clone the repository**  
git clone https://github.com/an0therprsn/tls-certificate-generator.git  
cd tls-certificate-generator  
  
**2. (Optional) Create a virtual environment**  
python -m venv venv  
source venv/bin/activate   # On Windows: venv\Scripts\activate  
  
**3. Install dependencies**  
pip install -r requirements.txt  
  
## Usage  
Run the tool with:  
python certgen.py  
  
You'll be guided through:  
- Selecting RSA or ECC  
- Choosing key size or curve  
- Entering subject details (CN, Organization, etc.)  
- Optionally adding SAN entries  
- Choosing between CSR or self-signed certificate  
- Specifying the output directory for files  
  
The tool will validate and display the certificate/CSR content using OpenSSL.  
  
## Output  
All generated files (private key, CSR or certificate) will be saved in the specified directory, for example:  
  
my-cert-folder/  
├── mysite_com.key  
├── mysite_com.csr  # (if CSR mode)  
└── mysite_com.crt  # (if self-signed mode)  
  
## Contributions  
Contributions are welcome! Feel free to fork the repository, open issues, or submit pull requests.
