#define CMAC_MODE  0
#define ECDSA_MODE 1

typedef struct
{
	unsigned char key_header[96];       //0
	unsigned int  cmd;                  //60
	unsigned int  mode;                 //64
	unsigned char unk0[8];              //68
	unsigned int  data_size;            //70
	unsigned int  metadatadata_size;    //74
	unsigned char unk1[8];              //78
	unsigned char unk2[16];             //80
} KIRK_CMD1_HEADER;	//0x90

typedef struct
{
	unsigned char aes_key[16];          //0   obfuscated
	unsigned char cmac_key[16];         //10  obfuscated
	unsigned char cmac_header_hash[16]; //20
	unsigned char cmac_block_hash[16];  //30
	unsigned char unk0[32];             //40
} CMAC_KEY_HEADER; //0x60

typedef struct
{
	unsigned char      aes_key[16];     //0   obfuscated
	unsigned char header_sig_r[20];     //10
	unsigned char header_sig_s[20];     //24
	unsigned char  block_sig_r[20];     //38
	unsigned char  block_sig_s[20];     //4C
} ECDSA_KEY_HEADER; //0x60

typedef struct
{
	unsigned int  load_address;
	unsigned int  data_size;
	unsigned int  entry_point;          //if not zer0
	unsigned int  checksum;             //if not zer0
} BLOCK_HEADER;  //0x10


unsigned char kirk1_key[] = {0x98, 0xC9, 0x40, 0x97, 0x5C, 0x1D, 0x10, 0xE8, 0x7F, 0xE6, 0x0E, 0xA3, 0xFD, 0x03, 0xA8, 0xBA};

unsigned char kirk1_p[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
unsigned char kirk1_a[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
unsigned char kirk1_b[] = {0x65, 0xD1, 0x48, 0x8C, 0x03, 0x59, 0xE2, 0x34, 0xAD, 0xC9, 0x5B, 0xD3, 0x90, 0x80, 0x14, 0xBD, 0x91, 0xA5, 0x25, 0xF9};
unsigned char kirk1_N[] = {0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0xB5, 0xC6, 0x17, 0xF2, 0x90, 0xEA, 0xE1, 0xDB, 0xAD, 0x8F};
unsigned char kirk1_Gx[] = {0x22, 0x59, 0xAC, 0xEE, 0x15, 0x48, 0x9C, 0xB0, 0x96, 0xA8, 0x82, 0xF0, 0xAE, 0x1C, 0xF9, 0xFD, 0x8E, 0xE5, 0xF8, 0xFA };
unsigned char kirk1_Gy[] = {0x60, 0x43, 0x58, 0x45, 0x6D, 0x0A, 0x1C, 0xB2, 0x90, 0x8D, 0xE9, 0x0F, 0x27, 0xD7, 0x5C, 0x82, 0xBE, 0xC1, 0x08, 0xC0 };
unsigned char kirk1_Px[] = {0xED, 0x9C, 0xE5, 0x82, 0x34, 0xE6, 0x1A, 0x53, 0xC6, 0x85, 0xD6, 0x4D, 0x51, 0xD0, 0x23, 0x6B, 0xC3, 0xB5, 0xD4, 0xB9 };
unsigned char kirk1_Py[] = {0x04, 0x9D, 0xF1, 0xA0, 0x75, 0xC0, 0xE0, 0x4F, 0xB3, 0x44, 0x85, 0x8B, 0x61, 0xB7, 0x9B, 0x69, 0xA6, 0x3D, 0x2C, 0x39 };