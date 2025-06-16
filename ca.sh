#!/bin/bash
# Guide to creating a JS Private CA for XMPro in Ubuntu

# Parse command line arguments
SILENT=true
VERBOSE=false
CA_PASSWORD="xmpro123"

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            SILENT=false
            shift
            ;;
        -s|--silent)
            SILENT=true
            VERBOSE=false
            shift
            ;;
        -p|--password)
            CA_PASSWORD="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -v, --verbose         Run in verbose mode with prompts"
            echo "  -s, --silent          Run in silent mode (default)"
            echo "  -p, --password PASS   Set CA private key password (default: xmpro123)"
            echo "  -h, --help            Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Set OpenSSL batch mode based on silent flag
if [ "$SILENT" = true ]; then
    OPENSSL_BATCH="-batch"
else
    OPENSSL_BATCH=""
fi

# STEP 1: Install OpenSSL if not already installed
sudo apt update -qq
sudo apt install -y openssl

# STEP 2: Create the directory structure for your CA
mkdir -p ~/js-private-ca/{certs,crl,newcerts,private,csr}
cd ~/js-private-ca
chmod 700 private
touch index.txt
echo 1000 > serial

# STEP 3: Create or update the OpenSSL configuration file
cat > openssl.cnf << 'EOL'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ~/js-private-ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

private_key       = $dir/private/ca.key
certificate       = $dir/certs/ca.crt

crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl
crl_extensions    = crl_ext
default_crl_days  = 30

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 3650
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = AU
stateOrProvinceName             = State or Province Name
stateOrProvinceName_default     = New South Wales
localityName                    = Locality Name
localityName_default            = Sydney
organizationName                = Organization Name
organizationName_default        = XMPro
organizationalUnitName          = Organizational Unit Name
organizationalUnitName_default  = XMPro IT Security
commonName                      = Common Name
commonName_default              = JS Private CA
emailAddress                    = Email Address
emailAddress_default            = js@xmpro.com

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ client_cert ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOL

# Fix the directory path by replacing ~ with the actual path
HOMEDIR=$(eval echo ~)
sed -i "s|~/js-private-ca|$HOMEDIR/js-private-ca|g" openssl.cnf

# STEP 4: Generate the Root CA private key
if [ "$SILENT" = true ]; then
    openssl genrsa -aes256 -out private/ca.key -passout pass:$CA_PASSWORD 4096
else
    openssl genrsa -aes256 -out private/ca.key 4096
fi

# STEP 5: Create the Root CA certificate
if [ "$SILENT" = true ]; then
    openssl req -config openssl.cnf -key private/ca.key -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.crt -passin pass:$CA_PASSWORD $OPENSSL_BATCH
else
    openssl req -config openssl.cnf -key private/ca.key -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.crt
fi

# STEP 6: Verify the root certificate
if [ "$VERBOSE" = true ]; then
    openssl x509 -noout -text -in certs/ca.crt
fi

# STEP 7: Create an intermediate CA (optional but recommended)
mkdir -p ~/js-private-ca/intermediate/{certs,crl,csr,newcerts,private}
cd ~/js-private-ca/intermediate
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

# STEP 8: Create intermediate CA configuration file
cat > openssl.cnf << 'EOL'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ~/js-private-ca/intermediate
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

private_key       = $dir/private/intermediate.key
certificate       = $dir/certs/intermediate.crt

crlnumber         = $dir/crlnumber
crl               = $dir/crl/intermediate.crl
crl_extensions    = crl_ext
default_crl_days  = 30

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

email_in_dn       = no
rand_serial       = yes

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = AU
stateOrProvinceName             = State or Province Name
stateOrProvinceName_default     = New South Wales
localityName                    = Locality Name
localityName_default            = Sydney
organizationName                = Organization Name
organizationName_default        = XMPro
organizationalUnitName          = Organizational Unit Name
organizationalUnitName_default  = XMPro IT Department
commonName                      = Common Name
commonName_default              = JS Intermediate CA
emailAddress                    = Email Address
emailAddress_default            = js@xmpro.com

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
# subjectAltName = copy

[ client_cert ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOL

# Fix the directory path by replacing ~ with the actual path
sed -i "s|~/js-private-ca|$HOMEDIR/js-private-ca|g" openssl.cnf

# STEP 9: Generate the intermediate CA private key
if [ "$SILENT" = true ]; then
    openssl genrsa -aes256 -out private/intermediate.key -passout pass:$CA_PASSWORD 4096
else
    openssl genrsa -aes256 -out private/intermediate.key 4096
fi

# STEP 10: Create a certificate signing request (CSR) for the intermediate CA
if [ "$SILENT" = true ]; then
    openssl req -config openssl.cnf -new -sha256 -key private/intermediate.key -out csr/intermediate.csr -passin pass:$CA_PASSWORD $OPENSSL_BATCH
else
    openssl req -config openssl.cnf -new -sha256 -key private/intermediate.key -out csr/intermediate.csr
fi

# STEP 11: Sign the intermediate certificate with the root CA
cd ~/js-private-ca
if [ "$SILENT" = true ]; then
    openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.csr -out intermediate/certs/intermediate.crt -passin pass:$CA_PASSWORD $OPENSSL_BATCH
else
    openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.csr -out intermediate/certs/intermediate.crt
fi

# STEP 12: Verify the intermediate certificate
if [ "$VERBOSE" = true ]; then
    openssl verify -CAfile certs/ca.crt intermediate/certs/intermediate.crt
fi

# STEP 13: Create the certificate chain file
cat intermediate/certs/intermediate.crt certs/ca.crt > intermediate/certs/ca-chain.crt

# Change to the intermediate directory for creating server and client certificates
cd ~/js-private-ca/intermediate

# STEP 14: Issue a server certificate (example)
mkdir -p private certs csr
openssl genrsa -out private/xmpro-server.key 2048
if [ "$SILENT" = true ]; then
    openssl req -config openssl.cnf -key private/xmpro-server.key -new -sha256 -out csr/xmpro-server.csr $OPENSSL_BATCH
    openssl ca -config openssl.cnf -extensions server_cert -days 375 -notext -md sha256 -in csr/xmpro-server.csr -out certs/xmpro-server.crt -passin pass:$CA_PASSWORD $OPENSSL_BATCH
else
    openssl req -config openssl.cnf -key private/xmpro-server.key -new -sha256 -out csr/xmpro-server.csr
    openssl ca -config openssl.cnf -extensions server_cert -days 375 -notext -md sha256 -in csr/xmpro-server.csr -out certs/xmpro-server.crt
fi
if [ "$VERBOSE" = true ]; then
    openssl verify -CAfile certs/ca-chain.crt certs/xmpro-server.crt
fi

# STEP 15: Issue a client certificate (example)
openssl genrsa -out private/xmpro-client.key 2048
if [ "$SILENT" = true ]; then
    openssl req -config openssl.cnf -key private/xmpro-client.key -new -sha256 -out csr/xmpro-client.csr $OPENSSL_BATCH
    openssl ca -config openssl.cnf -extensions client_cert -days 375 -notext -md sha256 -in csr/xmpro-client.csr -out certs/xmpro-client.crt -passin pass:$CA_PASSWORD $OPENSSL_BATCH
else
    openssl req -config openssl.cnf -key private/xmpro-client.key -new -sha256 -out csr/xmpro-client.csr
    openssl ca -config openssl.cnf -extensions client_cert -days 375 -notext -md sha256 -in csr/xmpro-client.csr -out certs/xmpro-client.crt
fi
if [ "$VERBOSE" = true ]; then
    openssl verify -CAfile certs/ca-chain.crt certs/xmpro-client.crt
fi

echo "JS Private CA for XMPro setup complete!"
echo "Root CA: $HOMEDIR/js-private-ca/certs/ca.crt"
echo "Intermediate CA: $HOMEDIR/js-private-ca/intermediate/certs/intermediate.crt"
echo "Certificate Chain: $HOMEDIR/js-private-ca/intermediate/certs/ca-chain.crt"
echo "Example Server Certificate: $HOMEDIR/js-private-ca/intermediate/certs/xmpro-server.crt"
echo "Example Client Certificate: $HOMEDIR/js-private-ca/intermediate/certs/xmpro-client.crt"
