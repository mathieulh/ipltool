#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ipltool.h"
#include "aes.h"
#include "sha1.h"
#include "ec.h"

void decrypt_header(unsigned char* header_buf, unsigned int buf_size)
{
	unsigned char *iv = (unsigned char*) malloc(0x10);
	memset(iv, 0, 0x10);
	aescbc128_decrypt(kirk1_key, iv, header_buf, header_buf, buf_size);
}

unsigned int calculate_checksum(void *dst, const void *src, int size)
{
	int i = 0;
	unsigned int checksum = 0;

	for (i=0; i<size; i+=4)
		checksum += *(unsigned int*)((unsigned char*)src + i);

 return(checksum);
}

void decrypt_data(FILE *in, unsigned int offset, unsigned int size, unsigned char *key, FILE *out)
{
	unsigned char iv[0x10];
	memset(iv, 0, 0x10);
	unsigned int pad = (0x10 - (size % 0x10)) % 0x10;
	unsigned char *data_in_buf = (unsigned char*) malloc(size+ pad);
	unsigned char *data_out_buf = (unsigned char*) malloc(size+ pad);
	
	memset(data_in_buf, 0, (size+ pad));
	memset(data_out_buf, 0, (size+ pad));
	fseek(in, offset, SEEK_SET);
	fread(data_in_buf, (size + pad), 1, in);
	
	aescbc128_decrypt(key, iv, data_in_buf, data_in_buf, (size + pad));
	
	BLOCK_HEADER* blk_header = (BLOCK_HEADER*)data_in_buf;
	
	//Check for type
	if (size <= 0xF60)
	{
		printf("\n");													//type 2+
		printf("[*] Block Header:\n");
		printf("Load address:    0x%X\n", blk_header->load_address);
		printf("Data size:       0x%X\n", blk_header->data_size);
		//if (blk_header->entry_point != 0)
		printf("Entry point:     0x%X\n", blk_header->entry_point);
	
		//if (blk_header->checksum != 0)
		printf("Prev blk chksum: 0x%X\n", blk_header->checksum);	
	
		//printf("[*] Block Checksum : 0x%X \n",  (_memcpy(data_out_buf, (data_in_buf + 0x10), (size - 0x10))));
		memcpy(data_out_buf, (data_in_buf + 0x10), size);
		size = blk_header->data_size;
	}
	else
		memcpy(data_out_buf, data_in_buf, size);  //type 1
	
	fwrite(data_out_buf, size, 1, out);
	free(data_in_buf);
	free(data_out_buf);
}

void print_usage(char *argv[])
{
	printf("USAGE: %s -d <file_in> <file_out> \n", argv[0]);
	printf("       %s -e <file_in> <file_out> <type> [entry_point]\n\n", argv[0]);
	printf("type should be 1, 2 or 3\n");
	printf("type 1: one huge block\n");
	printf("type 2: small blocks, last one is regular block\n");
	printf("type 3: small blocks, last one is ECDSA signed block with entry point\n");
}


int main(int argc, char *argv[])
{
	FILE *in = NULL;
	FILE *out = NULL;
	unsigned int in_size;
	
	printf("IPL Tool v. 0.0.1 alpha\n\n");
	
	if ((argc != 4) && (argc != 5) && (argc != 6))
	{
		print_usage(argv);
		return 0;
	}
	
	if ((strcmp(argv[1], "-e") == 0)&&(argc >= 5))
	{
		printf("Encryption mode\n");
		in = fopen(argv[2], "rb");
		//Check input file for permission.
		if (in == NULL)
		{
			printf("Error! Could not open file %s.\n", argv[2]);
			return 0;
		}
		else
			printf("File %s loaded.\n", argv[2]);
		
		//Obtain size of the input file.
		fseek(in, 0, SEEK_END);
		in_size = ftell(in);
		fseek(in, 0, SEEK_SET);
		
		//Check input file for size.
		if (in_size < 0x4 || in_size > 0x40000000)
		{
			printf("Error! Invalid IPL file detected, exiting.\n");
			fclose(in);
			return 0;
		}
		printf("File size : 0x%X bytes\n", in_size);
		
		//Create output file.
		out = fopen(argv[3], "wb");
	
		//Check output file for permission.
		if (out == NULL)
		{
			printf("Error! Could not create file %s.\n", argv[3]);
			fclose(in);
			return 0;
		}
		fclose(out);
	
		//Open output file.
		out = fopen(argv[3], "ab");
		
		//Branching Types
		if (strcmp(argv[4], "1") == 0)
		{
			printf("Selected type: 1 (one huge block)\n");
			printf("Not implemented yet...\n");
		}
		else if (strcmp(argv[4], "2") == 0)
		{
			printf("Selected type: 2 (small blocks, last one is regular block)\n");
			printf("not implemented yet\n");
		}
		else if (strcmp(argv[4], "3") == 0)
		{
			printf("Selected type: 3 (small blocks, last one is ECDSA signed block with entry point)\n");
			printf("Not implemented yet...\n");
		}
		else
		{
			printf("Error! Incorrect type selected, exiting\n");
			fclose(in);
			fclose(out);
		}

		fclose(in);
		fclose(out);
	}
	else if ((strcmp(argv[1], "-d") == 0)&&(argc == 4))
	{
		printf("Decryption mode\n");
		in = fopen(argv[2], "rb");
		//Check input file for permission.
		if (in == NULL)
		{
			printf("Error! Could not open file %s.\n", argv[2]);
			return 0;
		}
		else
			printf("File %s loaded.\n", argv[2]);
		
		//Obtain size of the input file.
		fseek(in, 0, SEEK_END);
		in_size = ftell(in);
		fseek(in, 0, SEEK_SET);
		
		//Check input file for size.
		if (in_size < 0x100 || in_size > 0x40000000)
		{
			printf("Error! Invalid IPL file detected, exiting.\n");
			fclose(in);
			return 0;
		}
		printf("File size : 0x%X bytes\n", in_size);
		
		//Create output file.
		out = fopen(argv[3], "wb");
	
		//Check output file for permission.
		if (out == NULL)
		{
			printf("Error! Could not create file %s.\n", argv[3]);
			fclose(in);
			return 0;
		}
		fclose(out);
	
		//Open output file.
		out = fopen(argv[3], "ab");
		unsigned int header_offset = 0;
		unsigned int pad_size = 0;
		unsigned int real_data_offset = 0;
		bool IsLastBlock = false;
		
		while (IsLastBlock == false)
		{
			unsigned char *header_buf = (unsigned char*) malloc(0x90);
			memset(header_buf, 0, 0x90);
			fseek(in, header_offset, SEEK_SET);
			fread(header_buf, 0x90, 1, in);

			KIRK_CMD1_HEADER* header = (KIRK_CMD1_HEADER*)header_buf;
			pad_size = (0x10 - (header->data_size % 0x10)) % 0x10;
			printf("\n");
			printf("[*] Kirk Header:\n");
		
		
			if (header->mode == CMAC_MODE)
			{
				printf("Kirk mode: CMAC\n");
				CMAC_KEY_HEADER* cmac_header = (CMAC_KEY_HEADER*)header->key_header;
			
				//Decrypt keys.
				decrypt_header(header_buf, 0x20);
			
				int i;
				printf("CIPHER KEY:  ");
				for (i = 0; i < 0x10; i++)
					printf("%02X", cmac_header->aes_key[i]);
				printf("\n");
		
				printf("HASHER KEY:  ");
				for (i = 0; i < 0x10; i++)
					printf("%02X", cmac_header->cmac_key[i]);
				printf("\n");
		
				//Check CMAC hashes
				printf("HEADER CMAC: ");
				for (i = 0; i < 0x10; i++)
					printf("%02X", cmac_header->cmac_header_hash[i]);
				printf("\n");

				unsigned char *cmac_hash = (unsigned char*) malloc(0x10);
				memset(cmac_hash, 0, 0x10);

				cmac_hash_forge((header_buf + 0x10), 0x10, (header_buf + 0x60), 0x30, cmac_hash);
				printf("COMPUTED:    ");
				for (i = 0; i < 0x10; i++)
					printf("%02X", cmac_hash[i]);
				printf("\n");

				printf("BLOCK CMAC:  ");
				for (i = 0; i < 0x10; i++)
					printf("%02X", cmac_header->cmac_block_hash[i]);
				printf("\n");

				memset(cmac_hash, 0, 0x10);
		
				unsigned int block_buf_size = 0x30 + header->metadatadata_size + header->data_size + pad_size;
				unsigned char *block_buf = new unsigned char[block_buf_size];
				memset(block_buf, 0, block_buf_size);
				fseek(in, header_offset + 0x60, SEEK_SET);
				fread(block_buf, block_buf_size , 1, in);
		
				cmac_hash_forge((header_buf + 0x10), 0x10, block_buf, block_buf_size, cmac_hash);
				printf("COMPUTED:    ");
				for (i = 0x0; i < 0x10; i++)
					printf("%02X", cmac_hash[i]);
				printf("\n");	
			
				free(block_buf);
			}
			else if (header->mode == ECDSA_MODE)
			{
				printf("Kirk mode: ECDSA\n");
				ECDSA_KEY_HEADER* ecdsa_header = (ECDSA_KEY_HEADER*)header->key_header;
			
				//Decrypt keys.
				decrypt_header(header_buf, 0x10);
			
				int i;
				printf("CIPHER KEY:  ");
				for (i = 0; i < 0x10; i++)
					printf("%02X", ecdsa_header->aes_key[i]);
				printf("\n");
				
							//Header Signature
				printf("HEADER SIGNATURE:\n");
				printf("R:   ");
				for (i = 0; i < 0x14; i++)
					printf("%02X", ecdsa_header->header_sig_r[i]);
				printf("\n");
				printf("S:   ");
				for (i = 0; i < 0x14; i++)
					printf("%02X", ecdsa_header->header_sig_s[i]);
				printf("\n");
			
				unsigned char header_hash[0x14];
				memset(header_hash, 0, 0x14);
				sha1((header_buf + 0x60), 0x30, header_hash);
			
				// Setup ECDSA curve and public key.
				ecdsa_set_curve(kirk1_p, kirk1_a, kirk1_b, kirk1_N, kirk1_Gx, kirk1_Gy);
				unsigned char kirk1_pub[0x28];
				memset(kirk1_pub, 0, 0x28);
				memcpy(kirk1_pub, kirk1_Px, 0x14);
				memcpy((kirk1_pub + 0x14),kirk1_Py, 0x14);
				ecdsa_set_pub(kirk1_pub);
			
				// Setup signature
				unsigned char signature_r[0x15];
				unsigned char signature_s[0x15];
				memset(signature_r, 0, 0x15);
				memset(signature_s, 0, 0x15);
				memcpy(signature_r + 01, ecdsa_header->header_sig_r, 0x14);
				memcpy(signature_s + 01, ecdsa_header->header_sig_s, 0x14);
				
				//Check header signature
				if (!ecdsa_verify(header_hash, signature_r, signature_s))
				{
					printf("STATUS: FAIL\n");
				}
				else
					printf("STATUS: OK\n");
				
				//Block Signature
				printf("BLOCK SIGNATURE:\n");
				printf("R:   ");
				for (i = 0; i < 0x14; i++)
					printf("%02X", ecdsa_header->block_sig_r[i]);
				printf("\n");
				printf("S:   ");
				for (i = 0; i < 0x14; i++)
					printf("%02X", ecdsa_header->block_sig_s[i]);
				printf("\n");

				unsigned char block_hash[0x14];
				memset(block_hash, 0, 0x14);
			
				unsigned int block_buf_size = 0x30 + header->metadatadata_size + header->data_size + pad_size;
				unsigned char *block_buf = new unsigned char[block_buf_size];
				memset(block_buf, 0, block_buf_size);
				fseek(in, header_offset + 0x60, SEEK_SET);
				fread(block_buf, block_buf_size , 1, in);
				sha1(block_buf, block_buf_size, block_hash);

				// Setup signature
				memset(signature_r, 0, 0x15);
				memset(signature_s, 0, 0x15);
				memcpy(signature_r + 01, ecdsa_header->block_sig_r, 0x14);
				memcpy(signature_s + 01, ecdsa_header->block_sig_s, 0x14);

				//Check block signature
				if (!ecdsa_verify(block_hash, signature_r, signature_s))
				{
					printf("STATUS: FAIL\n");
				}
				else
					printf("STATUS: OK\n");

			}
			else
			{
					printf("Error! Unknown Kirk mode.\n");
					return 0;
			}
		
		
			//Decrypt data
			printf("Encrypted data size: 0x%X bytes\n", header->data_size);
			printf("Encrypted metadata size: 0x%X bytes\n", header->metadatadata_size);
			real_data_offset = (header_offset + 0x90 + header->metadatadata_size);
			decrypt_data(in, real_data_offset, header->data_size, header->key_header, out);
			
			header_offset = header_offset + 0x1000;
			if ((header_offset >= in_size) || header_offset < header->data_size )
				IsLastBlock = true;
			free(header_buf);
			
		}	
		
		fclose(in);
		fclose(out);
	}
	else
		printf("Unknown mode, exiting\n");
	
	return 4; // Chosen by a fair dice roll
}             // Guaranteed to be a random

