# Advanced Active Directory Reconnaissance and Attack Script

This script provides a comprehensive suite of tools for Active Directory (AD) reconnaissance and exploitation, inspired by various techniques outlined in Juggernaut Sec's tutorials. It integrates LDAP enumeration, SMB and NetBIOS scanning, Kerberos attacks, credential dumping, and other advanced methods for assessing AD security.

## Features

- **LDAP Enumeration**: Discover users, groups, computers, domain controllers, and other AD objects.
- **NetBIOS and SMB Enumeration**: Enumerate SMB shares, active sessions, connected users, and access to common shares.
- **Kerberos Attacks**:
  - **Kerberoasting**: Extract service tickets for offline cracking.
  - **AS-REP Roasting**: Target accounts that do not require pre-authentication.
- **Credential Dumping**: Extract credentials from NTDS.dit, SAM database, and LSA secrets using Impacket’s `secretsdump.py`.

## Prerequisites

- Python 3.x
- Install required Python libraries:
  ```bash
  pip install ldap3 impacket
  ```
- Impacket tools must be accessible in your Python environment (e.g., `GetUserSPNs.py`, `GetNPUsers.py`, `secretsdump.py`).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ad-recon-script.git
   cd ad-recon-script
   ```
2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic LDAP and SMB Enumeration

Run the script with minimal parameters to perform basic AD enumeration using LDAP and SMB (anonymous bind):

```bash
python ad_recon.py --server <LDAP_SERVER>
```

### Authenticated LDAP and SMB Enumeration

To use authenticated binds, provide username, password, and domain:

```bash
python ad_recon.py --server <LDAP_SERVER> --username <USERNAME> --password <PASSWORD> --domain <DOMAIN>
```

### Perform Kerberoasting

Run Kerberoasting to extract service tickets for offline cracking:

```bash
python ad_recon.py --server <LDAP_SERVER> --username <USERNAME> --password <PASSWORD> --domain <DOMAIN> --kerberoast
```

### Perform AS-REP Roasting

Use AS-REP Roasting to target accounts that do not require pre-authentication:

```bash
python ad_recon.py --server <LDAP_SERVER> --asrep <USER_FILE>
```

### Dump Secrets

Dump NTDS.dit, SAM database, and LSA secrets using Impacket’s `secretsdump.py`:

```bash
python ad_recon.py --server <LDAP_SERVER> --username <USERNAME> --password <PASSWORD> --domain <DOMAIN> --dump
```

## Options

- `--server` (required): LDAP/DC server address.
- `--username`: Username for LDAP/SMB bind (optional for anonymous).
- `--password`: Password for LDAP/SMB bind (optional for anonymous).
- `--domain`: Domain for LDAP/SMB bind (required if username is provided).
- `--kerberoast`: Perform Kerberoasting.
- `--asrep`: Perform AS-REP Roasting with specified user file.
- `--dump`: Dump secrets using `secretsdump`.

## Example Commands

**Basic Recon (Anonymous Bind):**

```bash
python ad_recon.py --server 192.168.1.100
```

**Authenticated Recon:**

```bash
python ad_recon.py --server 192.168.1.100 --username admin --password Passw0rd! --domain example.local
```

**Run Kerberoasting:**

```bash
python ad_recon.py --server 192.168.1.100 --username admin --password Passw0rd! --domain example.local --kerberoast
```

**Run AS-REP Roasting:**

```bash
python ad_recon.py --server 192.168.1.100 --asrep users.txt
```

**Dump Secrets:**

```bash
python ad_recon.py --server 192.168.1.100 --username admin --password Passw0rd! --domain example.local --dump
```

## Disclaimer

This script is intended for authorized penetration testing and red teaming purposes only. Unauthorized use of this script against systems without proper authorization is illegal and unethical.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss improvements, features, or bugs.

## Acknowledgments

This script is inspired by techniques and methods from Juggernaut Sec's [Active Directory Hacking](https://juggernaut-sec.com/category/active-directory-hacking/) series.

---

**Note**: Replace `https://github.com/yourusername/ad-recon-script.git` with your actual GitHub repository link.
