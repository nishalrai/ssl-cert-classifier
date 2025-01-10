import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.text import Text
from rich.panel import Panel



# To print the current working directory
path = os.getcwd()

# To pass the working directory as an argument
dir_list = os.listdir(path)
#print('Files and directories in', path)

crt_files = []
key_files = []

for cert_check in dir_list:
    # Check if the file ends with .crt extension (case insensitive)
    if cert_check.lower().endswith(".crt"):
        crt_files.append(cert_check)
    # Check if the file ends with .key extension (case insensitive)
    elif cert_check.lower().endswith(".key"):
        key_files.append(cert_check)
    else:
        pass  # Do nothing if the file is neither .crt nor .key

# Print the results
#print("Certificate files:", crt_files)
#print("Key files:", key_files)
print("\n")

# Front Console
def print_centered_title(title_text):
    console = Console()

    # Create a panel with the centered text
    panel = Panel(
        title_text,
        title="###############################################",
        subtitle="###############################################",
        title_align="center",
        subtitle_align="center",
        expand=False,
        padding=(1, 1)  # Adjust padding as needed
    )

    # Print the panel with centered text
    console.print(panel)
    print("\n")

# Usage
print_centered_title(Text("     Created by NITRATIC\n       SSL Cert Classifier", style="aquamarine1"))
# Create a Console object
console = Console()

# Define the headers
header_1 = Text("List of discovered domain certificates:", style="bold cyan on black")
header_2 = Text("Info of Domain and Intermediate Certificate", style="medium_spring_green")
header_3 = Text("Discovered Domain, Intermediate and Root certificate from the list", style="bold magenta on black")
header_4 = Text("Unmatched intermediate certificates:", style="aquamarine1")

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

console.print(Panel(header_1, title="Domain Cert Info", title_align="left", expand=False))
for list_domain_crt in domain_certificates:
    with open(list_domain_crt, "rb") as list_domain_crt_file:
        list_domain_crt_file_data = list_domain_crt_file.read()
        cert = x509.load_pem_x509_certificate(list_domain_crt_file_data, default_backend())
        domain_cn = get_common_name(cert)
    #print(f'   Domain \"{list_domain_crt}\": CN: '{domain_cn}', style="bold red")
    console.print(f'   Domain "{list_domain_crt}": "{domain_cn}"', style="bold red")
    #print(f'     {list_domain_crt} - CN: {domain_cn}    ')

console.print("\n")
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

console.print(Panel(header_2, title="Domain and Intermediate Cert Info", title_align="left", expand=False))
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
            console.print(f"       Domain \"{classify_cert}\": '{domain_common_name}'", style="bold red")
            console.print(f"       Intermediate certificate \"{classify_inter}\": '{inter_common_name}'\n", style="royal_blue1")
            #print(f"Domain '{classify_cert}': '{domain_common_name}'\nIntermediate certificate '{classify_inter}': '{inter_common_name}'\n")
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

# Define a function to print certificate details
def print_certificate_details(domain_common_name, domain_cert, inter_common_name, inter_crts, root_crt_common_name, root_classify_cert):
    console.print(f"       Domain Cert \"{domain_cert}\": \"{domain_common_name}\"", style="bold red")
    console.print(f"       Intermediate Cert \"{inter_crts}\": \"{inter_common_name}\"", style="royal_blue1")
    console.print(f"       Root Cert \"{root_classify_cert}\" : \"{root_crt_common_name}\"", style="plum2")


console.print(Panel(header_3, title="Domain, Intermediate and Root Cert Info", title_align="left", expand=False))
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
                print_certificate_details(domain_common_name, domain_cert, inter_common_name, inter_crts, root_crt_common_name, root_classify_cert)
                match_found = True
                break  # Exit the loop once a match is found

    # If no match was found, add the intermediate certificate to the unmatched list
    if not match_found:
        print("\n")
        print(f'Intermediate Certificate Issuer CN: {inter_issuer_common_name}\n')
        unmatched_certs.append(inter_crts)
        #unmatched_certs.append(root_classify_cert)

# Print the list of unmatched intermediate certificates

if unmatched_certs:
    console.print(Panel(header_4, title="Unmatched Cert Info", title_align="left", expand=False))
    for unmatched_cert in unmatched_certs:
        console.print(f"       Unmmatched Cert : \"{unmatched_cert}\"", style="bold red")
        #print(unmatched_cert)
else:
    print("All intermediate certificates have matching root certificates.")
            
