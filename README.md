# ipltool
All In One Purpose tool for decrypting, encrypting, signing and validating ipls

## Usage

IPL Tool v. 0.2.0 by draanPSP, Proxima, 173210, Sorvigolova, zecoxao, Mathieulh & LemonHaze
===========================================================================================


USAGE: ./ipltool -d <file_in> <file_out>

       ./ipltool -e <file_in> <file_out> [options]

Options:

       -nv                              Disables verbose logging
       
       -r                               Use 'retail flag'
       
       -block-size=<size>               Specify block size
       
       -load-address=<address>          Specify base load address
       
       -entrypoint=<entrypoint>         Specify entrypoint
       
       -ec                              Toggle ECDSA on last block


### Benchmarks

#### Decryption

Tested and reported fine against multiple ipl samples (9) including writei, kbooti, formati, dformati and matryoska ipls with weird block size
