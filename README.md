# ipltool
All In One Purpose tool for decrypting, encrypting, signing and validating ipls

## Usage

IPL Tool v. 0.1.0 by Felix, Sorvigolova, zecoxao, Mathieulh & LemonHaze
=======================================================================


USAGE: ./ipltool -d <file_in> <file_out>
       ./ipltool -e <file_in> <file_out> <entry point> [options]

Options:
       -nv                              Disables verbose logging
       -r                               Use 'retail flag'
       -block-size=<size>               Specify block size

### Benchmarks

#### Decryption

Tested and reported fine against multiple ipl samples (9) including writei, kbooti, formati, dformati and matryoska ipls with weird block size
