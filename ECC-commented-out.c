/*FROM LINE 1289 */

//				EC_KEY *ephemeral = NULL, *recip_pubkey = NULL;
//				const EC_GROUP *group = NULL;
//				size_t envelope_length, block_length, key_length;
//				unsigned char envelope_key[SHA256_DIGEST_LENGTH] = { 0 };
//				unsigned char iv[AES_IV_SIZE] = { 0 };
//				unsigned char block[EVP_MAX_BLOCK_LENGTH] = { 0 };
//
//				if ((key_length = EVP_CIPHER_key_length(ECDH_CIPHER)) * 2 > SHA256_DIGEST_LENGTH) {
//					printf("The key derivation method will not produce enough envelope key material for the chosen ciphers. {envelope = %i / required = %zu}", SHA256_DIGEST_LENGTH / 8, (key_length * 2) / 8);
//					return NULL;
//				}
//
//				// Create the ephemeral key used specifically for this block of data.
//				if (!(ephemeral = EC_KEY_new())) {
//					printf("EC_KEY_new failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					return NULL;
//				}
//
//				//Extract Public key from AL and copy group settings
//				recip_pubkey = EVP_PKEY_get1_EC_KEY(authenticated_list[j]->pub_key);
//				group = EC_KEY_get0_group(recip_pubkey);
//
//
//				if (EC_KEY_set_group(ephemeral, group) != 1) {
//					printf("EC_KEY_set_group failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EC_GROUP_free(group);
//					EC_KEY_free(ephemeral);
//					return NULL;
//				}
//
//				EC_GROUP_free(group);
//
//				if (EC_KEY_generate_key(ephemeral) != 1) {
//					printf("EC_KEY_generate_key failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EC_KEY_free(ephemeral);
//					return NULL;
//				}
//
//
//				// Use the intersection of the provided keys to generate the envelope data used by the ciphers below. The ecies_key_derivation() function uses
//				// SHA 256 to ensure we have a sufficient amount of envelope key material and that the material created is sufficiently secure.
//				if (ECDH_compute_key(envelope_key, SHA256_DIGEST_LENGTH, EC_KEY_get0_public_key(recip_pubkey), ephemeral, KDF1_SHA256) != SHA256_DIGEST_LENGTH) {
//					printf("An error occurred while trying to compute the envelope key. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EC_KEY_free(ephemeral);
//					EC_KEY_free(recip_pubkey);
//					return NULL;
//				}
//
//				// Determine the envelope and block lengths so we can allocate a buffer for the result.
//				if ((block_length = EVP_CIPHER_block_size(ECDH_CIPHER)) == 0 || block_length > EVP_MAX_BLOCK_LENGTH ||
//						(envelope_length = EC_POINT_point2oct(EC_KEY_get0_group(ephemeral), EC_KEY_get0_public_key(ephemeral), POINT_CONVERSION_COMPRESSED, NULL, 0, NULL)) == 0) {
//
//					printf("Invalid block or envelope length. {block = %zu / envelope = %zu}\n", block_length, envelope_length);
//					EC_KEY_free(ephemeral);
//					EC_KEY_free(recip_pubkey);
//					return NULL;
//				}
//
//
//				secure_t *cryptex;
//
//				// We use a conditional to pad the length if the input buffer is not evenly divisible by the block size.
//				if (!(cryptex = secure_alloc(envelope_length, EVP_MD_size(ECDH_HASHER), AES_KEY_SIZE, AES_KEY_SIZE + (AES_KEY_SIZE % block_length ? (block_length - (AES_KEY_SIZE % block_length)) : 0)))) {
//					printf("Unable to allocate a secure_t buffer to hold the encrypted result.\n");
//					EC_KEY_free(ephemeral);
//					EC_KEY_free(recip_pubkey);
//					return NULL;
//				}
//
//
//				// Store the public key portion of the ephemeral key.
//				if (EC_POINT_point2oct(EC_KEY_get0_group(ephemeral), EC_KEY_get0_public_key(ephemeral), POINT_CONVERSION_COMPRESSED, (char *)cryptex+sizeof(secure_head_t), envelope_length, NULL) != envelope_length) {
//					printf("An error occurred while trying to record the public portion of the envelope key. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EC_KEY_free(ephemeral);
//					EC_KEY_free(recip_pubkey);
//					free(cryptex);
//					return NULL;
//				}
//
//				// The envelope key has been stored so we no longer need to keep the keys around.
//				EC_KEY_free(ephemeral);
//				EC_KEY_free(recip_pubkey);
//
//				// For now we use an empty initialization vector.
//				memset(iv, 0, AES_IV_SIZE);
////				RAND_pseudo_bytes(&iv, AES_IV_SIZE);
//
//				// Setup the cipher context, the body length, and store a pointer to the body buffer location.
//				EVP_CIPHER_CTX cipher;
//				void *body;
//				int body_length;
//
//				EVP_CIPHER_CTX_init(&cipher);
//				body = secure_body_data(cryptex);
//				body_length = ((secure_head_t *)cryptex)->length.body;
//
//
//				// Initialize the cipher with the envelope key.
//				if (EVP_EncryptInit_ex(&cipher, ECDH_CIPHER, NULL, envelope_key, iv) != 1 ||
//						EVP_CIPHER_CTX_set_padding(&cipher, 0) != 1 ||
//						EVP_EncryptUpdate(&cipher, body, &body_length, current_key,
//								AES_KEY_SIZE - (AES_KEY_SIZE % block_length)) != 1)
//				{
//
//					printf("An error occurred while trying to secure the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EVP_CIPHER_CTX_cleanup(&cipher);
//					free(cryptex);
//					return NULL;
//
//				}
//
//
//				// Advance the pointer, then use pointer arithmetic to calculate how much of the body buffer has been used. The complex logic is needed so that we get
//				// the correct status regardless of whether there was a partial data block.
//				body += body_length;
//				if ((body_length = ((secure_head_t *)cryptex)->length.body - (body - secure_body_data(cryptex))) < 0) {
//					printf("The symmetric cipher overflowed!\n");
//					EVP_CIPHER_CTX_cleanup(&cipher);
//					free(cryptex);
//					return NULL;
//				}
//
//
//				if (EVP_EncryptFinal_ex(&cipher, body, &body_length) != 1) {
//					printf("Unable to secure the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EVP_CIPHER_CTX_cleanup(&cipher);
//					free(cryptex);
//					return NULL;
//				}
//
//				EVP_CIPHER_CTX_cleanup(&cipher);
//
//				// Generate an authenticated hash which can be used to validate the data during decryption.
//				HMAC_CTX hmac;
//				unsigned int mac_length;	mac_value = ;
//				HMAC_CTX_init(&hmac);
//				mac_length = ((secure_head_t *)cryptex)->length.mac;
//
//				// At the moment we are generating the hash using encrypted data. At some point we may want to validate the original text instead.
//				HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ECDH_HASHER, NULL);
//				HMAC_Update(&hmac, current_key, AES_KEY_SIZE);
//				HMAC_Final(&hmac, secure_mac_data(cryptex), &mac_length);
////				{
////
////					printf("Unable to generate a data authentication code. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
////					HMAC_CTX_cleanup(&hmac);
////					free(cryptex);
////					return NULL;
////				}
//
//				HMAC_CTX_cleanup(&hmac);
//
//				tool_dump_memory((unsigned char *)secure_body_data(cryptex), body_length);
//
//				exit(1);



				/* OLD ECC */

//				recip_pubkey = EVP_PKEY_get1_EC_KEY(authenticated_list[j]->pub_key);
//				group = EC_KEY_get0_group(recip_pubkey);
//
//				ephemeral_key = EC_KEY_new();
//				EC_KEY_set_group(ephemeral_key, group);
//
//				EC_KEY_generate_key(ephemeral_key);
//
//				// With this 256 bit long buffer, we have a 128bit (16 Byte) AES key and IV to encrypt the key being sent...
//				ECDH_compute_key(key_iv_buf, sizeof key_iv_buf, EC_KEY_get0_public_key(recip_pubkey), ephemeral_key, KDF1_SHA256);
//				unsigned char *key, *iv;
//				key = malloc(AES_KEY_SIZE);
//				iv = malloc(AES_IV_SIZE);
//				memcpy(key, key_iv_buf, AES_KEY_SIZE);
//				memcpy(iv, key_iv_buf+AES_KEY_SIZE, AES_IV_SIZE);
//
//				EVP_CIPHER_CTX aes_ctx;
//				EVP_EncryptInit(&aes_ctx, EVP_aes_128_ecb(), key, iv);
//				unsigned char *encrypted_key;
//				int encrypted_key_len = AES_KEY_SIZE;
//				encrypted_key = openssl_aes_encrypt(&aes_ctx, current_key, &encrypted_key_len);
//
//				free(key);
//				free(iv);
//