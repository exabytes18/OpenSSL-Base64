#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>

void openssl_base64_decode(char *encoded_bytes, char **decoded_bytes, ssize_t *decoded_length) {
	BIO *bioMem, *b64;
	ssize_t buffer_length;

	bioMem = BIO_new_mem_buf((void *)encoded_bytes, -1);
	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bioMem = BIO_push(b64, bioMem);

	buffer_length = BIO_get_mem_data(bioMem, NULL);
	*decoded_bytes = malloc(buffer_length);
	*decoded_length = BIO_read(bioMem, *decoded_bytes, buffer_length);
	BIO_free_all(bioMem);
}

char *openssl_base64_encode(char *decoded_bytes, ssize_t decoded_length) {
	int x;
	BIO *bioMem, *b64;
	BUF_MEM *bufPtr;
	char *buff;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bioMem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bioMem);
	
	BIO_write(b64, decoded_bytes, decoded_length);
	x = BIO_flush(b64);
	if(x < 1) {
		BIO_free_all(b64);
		return NULL;
	}
	
	BIO_get_mem_ptr(b64, &bufPtr);

	buff = (char *) malloc(bufPtr->length+1);
	memcpy(buff, bufPtr->data, bufPtr->length);
	buff[bufPtr->length] = 0;

	BIO_free_all(b64);
	return buff;
}

