import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from __scp_file__ import scp_transfer
from requests import get

## Add modules
import subprocess
import sys


def load_cert_files(folder_name="ssl"):
    """
    Load .crt and .key files from the specified folder in the current working directory.

    :param folder_name: Name of the folder to search for files.
    :return: Lists of .crt and .key files.
    """
    # Construct the path to the directory
    path = os.path.join(os.getcwd(), folder_name)
    
    if not os.path.exists(path):
        print(f"Error: The directory '{folder_name}' does not exist in the current working directory.")
        #return [], []
        sys.exit(1)

    # List all files in the directory
    try:
        dir_list = os.listdir(path)
    except PermissionError as e:
        print(f"Permission denied: {e}")
        sys.exit(1)
        #return [], []

    crt_files = []
    key_files = []

    # Filter files by extension
    for cert_check in dir_list:
        if cert_check.lower().endswith(".crt"):
            crt_files.append(cert_check)
        elif cert_check.lower().endswith(".key"):
            key_files.append(cert_check)

    return crt_files, key_files

if __name__ == "__main__":
    # Check if a folder name is passed as an argument
    if len(sys.argv) > 1:
        folder_name = sys.argv[1]  # Use the directory name passed as an argument
    else:
        folder_name = "ssl"  # Default to 'ssl' directory

    crt_files, key_files = load_cert_files(folder_name)

    #print(f"CRT files in '{folder_name}': {crt_files}")
    #print(f"Key files in '{folder_name}': {key_files}")

# Print the results
#print("Certificate files:", crt_files)
#print("Key files:", key_files)
print("\n")
# Lists to store classified certificates
domain_certificates = []
intermediate_certificates = []
root_certificates = []

# Function to extract the CN value from a certificate
def get_common_name(cert):
    subject = cert.subject
    for attribute in subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            return attribute.value
    return None

# First pass: classify domain certificates
for crt_info in crt_files:
    with open(crt_info, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        cn = get_common_name(cert)
        
        # Adjusted condition to allow any domain pattern (not just .com)
        if cn and (cn.startswith("*") or cn.startswith("www")):
            domain_certificates.append(crt_info)
            #print(f"\nDomain Certificate:\n{crt_info} with CN: {cn}")

print("#####  List of discovered domain certificates:  ####")
for list_domain_crt in domain_certificates:
    with open(list_domain_crt, "rb") as list_domain_crt_file:
        list_domain_crt_file_data = list_domain_crt_file.read()
        cert = x509.load_pem_x509_certificate(list_domain_crt_file_data, default_backend())
        domain_cn = get_common_name(cert)
    print(f'     {list_domain_crt} - CN: {domain_cn}    ')


#print(domain_certificates)
#print(crt_files)

new_crt_files= list(set(crt_files) - set(domain_certificates))
#print(new_crt_files)


# Function to extract only the CN part from the issuer's DN
def get_common_name_from_issuer(issuer_dn):
    attributes = issuer_dn.split(',')
    for attr in attributes:
        if attr.startswith("CN="):
            return attr.split('=')[1]  # Extract the value after 'CN='
    return None


# Dictionary to store discovered domain certificates and their corresponding intermediate certificates
certificate_pairs = {}
intermediate_list =[]

# Assuming domain_certificates and new_crt_files are lists of file paths to certificates
for classify_cert in domain_certificates:
    with open(classify_cert, "rb") as classify_crt_file:
        # Load the domain certificate
        new_cert = x509.load_pem_x509_certificate(classify_crt_file.read(), default_backend())
        # Extract the issuer's DN and the CN from it
        issuer_dn = new_cert.issuer.rfc4514_string()
        common_name = get_common_name_from_issuer(issuer_dn)
        domain_common_name = get_common_name(new_cert)
        #print(f"Issuer CN: {domain_common_name}")
        #print(f"Issuer CN: {common_name}")
        
    
    # Iterate through intermediate certificates to find a match
    for classify_inter in new_crt_files:
        with open(classify_inter, "rb") as new_crt_info:
            # Load the intermediate certificate
            cert_info = x509.load_pem_x509_certificate(new_crt_info.read(), default_backend())
            # Extract the CN from the intermediate certificate
            inter_common_name = get_common_name(cert_info)
            #print(f"Intermediate CN: {inter_common_name}")
        
        # Check if the CNs match
        if common_name == inter_common_name:
            #print(f"Domain certificate '{classify_cert}': '{domain_common_name}' corresponds intermediate certificate '{classify_inter}': '{inter_common_name}'")
            # Add the discovered pair to the dictionary
            intermediate_list.append(classify_inter)
            certificate_pairs[classify_cert] = classify_inter
print("\n")
#print(certificate_pairs)
# At the end, 'certificate_pairs' will contain the mapping of domain certificates to their corresponding intermediate certificates

#print("Intermediate list", intermediate_list)
root_crt_files = list(set(new_crt_files) - set(intermediate_list) - set(domain_certificates))
#print(root_crt_files)



# List to keep track of unmatched intermediate certificates
unmatched_certs = []

print(f'#####   Discovered Domain, Intermediate and Root certificate from the list   #####')
for domain_cert, inter_crts in certificate_pairs.items():
    # Open and read the domain certificate
    with open(domain_cert, "rb") as domain_crt_file:
        domain_cert_info = x509.load_pem_x509_certificate(domain_crt_file.read(), default_backend())
        domain_subject_dn = domain_cert_info.subject.rfc4514_string()  # Use subject DN for CN extraction
        domain_common_name = get_common_name_from_issuer(domain_subject_dn)
        #print(f'Domain Certificate CN: {domain_common_name}')


    # Open and read the intermediate certificate
    with open(inter_crts, "rb") as inter_crt_file:
        cert_info = x509.load_pem_x509_certificate(inter_crt_file.read(), default_backend())
        inter_issuer_dn = cert_info.issuer.rfc4514_string()
        inter_issuer_common_name = get_common_name_from_issuer(inter_issuer_dn)
        inter_common_name_final = get_common_name_from_issuer(inter_issuer_dn)
    
        #print(f'Intermediate Certificate Issuer CN: {inter_issuer_common_name}')
    
    # Flag to track if a match was found
    match_found = False

    # Iterate through root certificate files
    for root_classify_cert in root_crt_files:
        with open(root_classify_cert, "rb") as root_crt_file:
            root_crt_info = x509.load_pem_x509_certificate(root_crt_file.read(), default_backend())
            root_crt_subject = get_common_name(root_crt_info)
            root_crt_issuer_dn = root_crt_info.issuer.rfc4514_string()
            root_crt_common_name = get_common_name_from_issuer(root_crt_issuer_dn)

            #print(f'Root Certificate Subject CN: {root_crt_subject}')
            #print(f'Root Certificate Issuer CN: {root_crt_common_name}')
            
            if inter_issuer_common_name == root_crt_subject and inter_issuer_common_name == root_crt_common_name:
                print(f'     Domain "{domain_common_name}": file "{domain_cert}":\n    Intermediate "{inter_common_name}": "{inter_crts}" \n    Root "{root_crt_common_name}" : "{root_classify_cert}"')
                match_found = True
                break  # Exit the loop once a match is found

    # If no match was found, add the intermediate certificate to the unmatched list
    if not match_found:
        print("\n")
        print(f'Intermediate Certificate Issuer CN: {inter_issuer_common_name}')
        unmatched_certs.append(inter_crts)
        #unmatched_certs.append(root_classify_cert)

# Print the list of unmatched intermediate certificates
if unmatched_certs:
    print("Unmatched intermediate certificates:")
    for unmatched_cert in unmatched_certs:
        print(unmatched_cert)
else:
    print("All intermediate certificates have matching root certificates.")
            
print(f'Certificate pairs')
print(certificate_pairs)
print(key_files)

# Function to get modulus md5 hash using OpenSSL
def get_modulus_md5(filepath, is_key=False):
    cmd = ['openssl', 'rsa' if is_key else 'x509', '-noout', '-modulus', '-in', filepath]
    process = subprocess.run(cmd, capture_output=True, text=True)
    modulus = process.stdout.strip()
    # Hash the modulus using md5
    md5_process = subprocess.run(['openssl', 'md5'], input=modulus, capture_output=True, text=True)
    return md5_process.stdout.strip()

# Array to store the result
result = []

# Iterate through the certificates and keys
for get_domain, get_inter in certificate_pairs.items():
    cert_md5 = get_modulus_md5(get_domain)
    for key in key_files:
        key_md5 = get_modulus_md5(key, is_key=True)
        if cert_md5 == key_md5:
            result.append([get_domain, get_inter, key])

print(result)

# Function to return the result list
def get_result():
    return result

# Destination details
destination_directory = "/usr/ssl"
ip_addr = input("Enter the destination IP Address: ")
username = input("Enter the SSH username: ")
password = input("Enter the SSH password: ")

# Verifying f5 connectivity
f5_check = get(f"https://{ip_addr}/mgmt/shared/appsvcs/declare", auth=("username", "password"))
print(f5_check.status_code())