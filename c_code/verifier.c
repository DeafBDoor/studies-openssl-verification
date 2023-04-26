#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

const int SIGNATURE_SIZE = 512;

int main(int argc, char *argv[])
{
	int rv;
	FILE *fp = NULL;
	EVP_PKEY *pub_key = NULL;
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pkeyctx = NULL;
	char buf[SIGNATURE_SIZE];
	size_t len;

	fp = fopen("../pub_key.pem", "r");
	if (fp == NULL) {
		printf("Error opening pubkey file\n");
		exit(1);
	}

	pub_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	if (pub_key == NULL) {
		printf("Error reading pubkey\n");
		exit(1);
	}
	fclose(fp);

	if (!(mdctx = EVP_MD_CTX_create())) {
		printf("Error creating MD context\n");
		exit(1);
	}

	rv = EVP_DigestVerifyInit(mdctx, &pkeyctx, EVP_sha512(), NULL, pub_key);
	if (!rv) {
		printf("Error to digest verify init\n");
		exit(1);
	}

	if (!EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyctx, RSA_PSS_SALTLEN_MAX) ||
		!EVP_PKEY_CTX_set_rsa_padding(pkeyctx, RSA_PKCS1_PSS_PADDING) ||
		!EVP_PKEY_CTX_set_rsa_mgf1_md(pkeyctx, EVP_sha512())) {
		printf("Error setting padding parameters for RSA key context or signature digest parameter!\n");
		exit(1);
	}
	
	fp = fopen("../myfile.txt", "r");
	if (fp == NULL) {
		printf("Error opening data file\n");
		exit(1);
	}
	printf("Reading data file...\n");
	do {
		len = fread(&buf, 1, sizeof(buf), fp);
		if (ferror(fp)) {
			printf("Error reading data file\n");
			exit(1);
		}
		rv = EVP_DigestVerifyUpdate(mdctx, buf, len);
	} while (!feof(fp));
	fclose(fp);
	printf("Finished data file digest.\n");

	fp = fopen("../myfile.txt.signature", "r");
	if (fp == NULL) {
		printf("Error opening signature file!\n");
		exit(1);
	}
	len = fread(&buf, 1, SIGNATURE_SIZE, fp);
	if (ferror(fp) || len != SIGNATURE_SIZE) {
		printf("Error reading signature file\n");
		exit(1);
	}
	if (len != SIGNATURE_SIZE) {
		printf("Signature file of wrong size\n");
		exit(1);
	}
	fclose(fp);

	rv = EVP_DigestVerifyFinal(mdctx, (unsigned char *)buf, len);
	if (rv == 1) {
		printf("Signature is valid!\n");
	} else if (rv == 0) {
		printf("Signature is not valid!\n");
	} else {
		printf("Signature verification failed with code %d\n", rv);
	}

	// No need to free EVP_PKEY_CTX, since its freed automatically when the EVP_MD_CTX is freed.
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pub_key); 

	return 0;
}
