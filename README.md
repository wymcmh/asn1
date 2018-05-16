# asn1
This is an asn.1 decoding tool that can parse the BER/DER stream,  display its message structure, field types, and values without relying on the original protocol file.

## Usage

First time to use, you need to give executable permissions to the script:

    chmod +x *.py

Usage:

    ./print_struct.py der_file [is_bin = 1]

You can use this tool to parse any BER/DER stream. Target file format can be a hex string or raw binary.
For example, parsing a common certificate file (X509):

    ./print_stuct.py cert.cer
    
Or save a hex string to ber.hex file:

    ./print_stuct.py ber.hex 0
