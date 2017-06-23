# ipltool
All In One Purpose tool for decrypting, encrypting, signing and validating ipls

## Usage

IPL Tool v. 0.2.0 by draanPSP, Proxima, 173210, Sorvigolova, zecoxao, Mathieulh & LemonHaze
===========================================================================================


USAGE: 

       ./ipltool -d <file_in> <file_out> [dec options]
       ./ipltool -e <file_in> <file_out> [enc options]

Decryption Options:
       
       -nv                              Disables verbose logging

Encryption Options:
       
       -nv                              Disables verbose logging
       -r                               Use 'retail flag'
       -s=<size>                        Specify block size
       -l=<address>                     Specify base load address
       -p=<entrypoint>                  Specify entrypoint
       -ec                              Toggle ECDSA on last block

       Default values:
        Entrypoint:                     0x040F0000
        Load Address:                   0x040F0000
        Data Size:                      0x00000F50



### Benchmarks

#### Decryption

Tested and reported fine against multiple ipl samples (9) including writei, kbooti, formati, dformati and matryoska ipls with weird block size
