#!/bin/bash
# Script to generate a CSR and issue a certificate using the JS Private CA for XMPro

# Default values (can be overridden with command line arguments)
CERT_TYPE="server"  # 'server' or 'client'
SERVER_NAME=""
COMMON_NAME=""
EMAIL="certauthority@xmpro.com"
COUNTRY="AU"
STATE="New South Wales"
LOCALITY="Sydney"
ORGANIZATION="XMPro"
ORG_UNIT="XMPro IT Department"
KEY_SIZE=2048
DAYS=375
CA_DIR=~/js-private-ca
OUTPUT_DIR="./certificates"
CA_PASSWORD="xmpro123"
PFX_PASSWORD=""

# Function to display usage
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -t, --type TYPE        Certificate type (server or client, default: server)"
    echo "  -n, --name NAME        Server name or client name (required)"
    echo "  -c, --common-name CN   Common Name for the certificate (default: same as name)"
    echo "  -e, --email EMAIL      Email address (default: certauthority@xmpro.com)"
    echo "  -o, --org ORG          Organization name (default: XMPro)"
    echo "  -u, --unit UNIT        Organizational unit (default: XMPro IT Department)"
    echo "  -k, --key-size SIZE    Key size in bits (default: 2048)"
    echo "  -d, --days DAYS        Certificate validity in days (default: 375)"
    echo "  -p, --pfx              Also create PFX/PKCS#12 file for Windows/IIS"
    echo "  --ca-password PASS     CA private key password (default: xmpro123)"
    echo "  --pfx-password PASS    PFX export password (required if --pfx is used)"
    echo "  --output-dir DIR       Directory to store generated certificates (default: ./certificates)"
    echo "  -h, --help             Display this help message"
    exit 1
}

# Parse command line arguments
CREATE_PFX=false
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -t|--type)
            CERT_TYPE="$2"
            shift 2
            ;;
        -n|--name)
            SERVER_NAME="$2"
            if [[ -z "$COMMON_NAME" ]]; then
                COMMON_NAME="$2"
            fi
            shift 2
            ;;
        -c|--common-name)
            COMMON_NAME="$2"
            shift 2
            ;;
        -e|--email)
            EMAIL="$2"
            shift 2
            ;;
        -o|--org)
            ORGANIZATION="$2"
            shift 2
            ;;
        -u|--unit)
            ORG_UNIT="$2"
            shift 2
            ;;
        -k|--key-size)
            KEY_SIZE="$2"
            shift 2
            ;;
        -d|--days)
            DAYS="$2"
            shift 2
            ;;
        -p|--pfx)
            CREATE_PFX=true
            shift
            ;;
        --ca-password)
            CA_PASSWORD="$2"
            shift 2
            ;;
        --pfx-password)
            PFX_PASSWORD="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate input
if [[ -z "$SERVER_NAME" ]]; then
    echo "Error: Server/client name is required."
    usage
fi

if [[ "$CERT_TYPE" != "server" && "$CERT_TYPE" != "client" ]]; then
    echo "Error: Certificate type must be 'server' or 'client'."
    usage
fi

if [[ "$CREATE_PFX" == true && -z "$PFX_PASSWORD" ]]; then
    echo "Error: PFX password is required when --pfx option is used."
    echo "Use --pfx-password PASS to specify the password."
    usage
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Ensure that the CA exists
if [[ ! -d "$CA_DIR" ]]; then
    echo "Error: JS Private CA not found at $CA_DIR"
    echo "Please run the CA setup script first."
    exit 1
fi

if [[ ! -d "$CA_DIR/intermediate" ]]; then
    echo "Error: Intermediate CA not found at $CA_DIR/intermediate"
    echo "Please run the CA setup script first."
    exit 1
fi

# Create a temporary configuration file for this CSR
CONFIG_FILE=$(mktemp)
cat > "$CONFIG_FILE" << EOL
[req]
default_bits        = $KEY_SIZE
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
req_extensions      = req_ext

[req_distinguished_name]
countryName                     = Country Name (2 letter code)
countryName_default             = $COUNTRY
stateOrProvinceName             = State or Province Name
stateOrProvinceName_default     = $STATE
localityName                    = Locality Name
localityName_default            = $LOCALITY
organizationName                = Organization Name
organizationName_default        = $ORGANIZATION
organizationalUnitName          = Organizational Unit Name
organizationalUnitName_default  = $ORG_UNIT
commonName                      = Common Name
commonName_default              = $COMMON_NAME
emailAddress                    = Email Address
emailAddress_default            = $EMAIL

[req_ext]
# subjectAltName = @alt_names
# [alt_names]
EOL

# Handle wildcard certificates
# if [[ "$SERVER_NAME" == \*.* ]]; then
#     echo "Wildcard certificate detected."
#     echo "DNS.1 = $SERVER_NAME" >> "$CONFIG_FILE"
#     echo "DNS.2 = ${SERVER_NAME#\*.}" >> "$CONFIG_FILE"
#     echo "DNS.3 = $COMMON_NAME" >> "$CONFIG_FILE"
#     echo "DNS.4 = localhost" >> "$CONFIG_FILE"
#     echo "IP.1 = 127.0.0.1" >> "$CONFIG_FILE"
#     echo "IP.2 = ::1" >> "$CONFIG_FILE"
# else
#     echo "DNS.1 = $SERVER_NAME" >> "$CONFIG_FILE"
#     echo "DNS.2 = $COMMON_NAME" >> "$CONFIG_FILE"
#     echo "DNS.3 = localhost" >> "$CONFIG_FILE"
#     echo "DNS.4 = "$(hostname)".local" >> "$CONFIG_FILE"
#     echo "IP.1 = 127.0.0.1" >> "$CONFIG_FILE"
#     echo "IP.2 = ::1" >> "$CONFIG_FILE"
# fi

# Handle wildcard certificates
if [[ "$SERVER_NAME" == \*.* ]]; then
    echo "Wildcard certificate detected."
    echo "subjectAltName = DNS:$SERVER_NAME,DNS:${SERVER_NAME#\*.},DNS:$COMMON_NAME,DNS:localhost,IP:127.0.0.1,IP:::1" >> "$CONFIG_FILE"
else
    echo "subjectAltName = DNS:$SERVER_NAME,DNS:$COMMON_NAME,DNS:localhost,DNS:"$(hostname | tr '[:upper:]' '[:lower:]')".local,IP:127.0.0.1,IP:::1" >> "$CONFIG_FILE"
fi


# Add appropriate extensions based on certificate type
if [[ "$CERT_TYPE" == "server" ]]; then
    cat >> "$CONFIG_FILE" << EOL

[server_ext]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "XMPro JS Private CA Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOL
# Handle wildcard certificates
if [[ "$SERVER_NAME" == \*.* ]]; then
    echo "Wildcard certificate detected."
    echo "subjectAltName = DNS:$SERVER_NAME,DNS:${SERVER_NAME#\*.},DNS:$COMMON_NAME,DNS:localhost,IP:127.0.0.1,IP:::1" >> "$CONFIG_FILE"
else
    echo "subjectAltName = DNS:$SERVER_NAME,DNS:$COMMON_NAME,DNS:localhost,DNS:"$(hostname | tr '[:upper:]' '[:lower:]')".local,IP:127.0.0.1,IP:::1" >> "$CONFIG_FILE"
fi
else
    cat >> "$CONFIG_FILE" << EOL

[client_ext]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "XMPro JS Private CA Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOL
fi

echo "Generating private key for $SERVER_NAME..."
openssl genrsa -out "$OUTPUT_DIR/$SERVER_NAME.key" $KEY_SIZE

echo "Generating certificate signing request (CSR)..."
cat $CONFIG_FILE
openssl req -config "$CONFIG_FILE" -key "$OUTPUT_DIR/$SERVER_NAME.key" -new -sha256 -out "$OUTPUT_DIR/$SERVER_NAME.csr" -extensions req_ext -batch

echo "Issuing certificate from the JS Private CA..."
if [[ "$CERT_TYPE" == "server" ]]; then
    openssl ca -config "$CA_DIR/intermediate/openssl.cnf" -extfile "$CONFIG_FILE" -extensions server_ext -days $DAYS -notext -md sha256 -in "$OUTPUT_DIR/$SERVER_NAME.csr" -out "$OUTPUT_DIR/$SERVER_NAME.crt" -batch -passin pass:$CA_PASSWORD
else
    openssl ca -config "$CA_DIR/intermediate/openssl.cnf" -extensions client_cert -days $DAYS -notext -md sha256 -in "$OUTPUT_DIR/$SERVER_NAME.csr" -out "$OUTPUT_DIR/$SERVER_NAME.crt" -batch -passin pass:$CA_PASSWORD
fi

# Verify the certificate
echo "Verifying certificate..."
openssl verify -CAfile "$CA_DIR/intermediate/certs/ca-chain.crt" "$OUTPUT_DIR/$SERVER_NAME.crt"

# Create certificate chain file
echo "Creating certificate chain file..."
cat "$OUTPUT_DIR/$SERVER_NAME.crt" "$CA_DIR/intermediate/certs/ca-chain.crt" > "$OUTPUT_DIR/$SERVER_NAME-chain.crt"

# Create PFX/PKCS#12 file for Windows/IIS if requested
if [[ "$CREATE_PFX" == true ]]; then
    echo "Creating PFX file for Windows/IIS..."
    openssl pkcs12 -export -out "$OUTPUT_DIR/$SERVER_NAME.pfx" -inkey "$OUTPUT_DIR/$SERVER_NAME.key" -in "$OUTPUT_DIR/$SERVER_NAME.crt" -certfile "$CA_DIR/intermediate/certs/ca-chain.crt" -passout pass:"$PFX_PASSWORD"
    echo "PFX file created: $OUTPUT_DIR/$SERVER_NAME.pfx"
fi

# Cleanup
rm "$CONFIG_FILE"

echo "Certificate generation complete!"
echo "Files created:"
echo "  Private Key:      $OUTPUT_DIR/$SERVER_NAME.key"
echo "  CSR:              $OUTPUT_DIR/$SERVER_NAME.csr"
echo "  Certificate:      $OUTPUT_DIR/$SERVER_NAME.crt"
echo "  Certificate Chain:$OUTPUT_DIR/$SERVER_NAME-chain.crt"
if [[ "$CREATE_PFX" == true ]]; then
    echo "  PFX File:         $OUTPUT_DIR/$SERVER_NAME.pfx"
fi

echo ""
echo "Examples:"
echo "  # Generate a server certificate for a specific domain"
echo "  $0 --name server.xmpro.com"
echo ""
echo "  # Generate a wildcard certificate"
echo "  $0 --name \"*.xmpro.com\""
echo ""
echo "  # Generate a client certificate"
echo "  $0 --type client --name developer-laptop"
echo ""
