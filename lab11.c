#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RED "\e[9;31m"
#define GRN "\e[0;32m"
#define CRESET "\e[0m"

#define handle_error(msg)                                                      \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

size_t read_all_bytes(const char *filename, void *buffer, size_t buffer_size) {
  FILE *file = fopen(filename, "rb");
  if (!file) {
    handle_error("Error opening file");
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  if (file_size > buffer_size) {
    handle_error("File size is too large");
  }

  if (fread(buffer, 1, file_size, file) != file_size) {
    handle_error("Error reading file");
  }

  fclose(file);
  return file_size;
}

void print_file(const char *filename, const char *color) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    handle_error("Error opening file");
  }

  printf("%s", color);
  char line[256];
  while (fgets(line, sizeof(line), file)) {
    printf("%s", line);
  }
  fclose(file);
  printf(CRESET);
}

int verify(const char *message_path, const char *sign_path, EVP_PKEY *pubkey);

int main() {
  // File paths
  const char *message_files[] = {"message1.txt", "message2.txt",
                                 "message3.txt"};
  const char *signature_files[] = {"signature1.sig", "signature2.sig",
                                   "signature3.sig"};

  // TODO: Load the public key using PEM_read_PUBKEY
  FILE *fp;
  fp = fopen("public_key.pem", "r");
  EVP_PKEY *pubkey = NULL;
  pubkey = PEM_read_PUBKEY_ex(fp, NULL, NULL, NULL, NULL, NULL);

  // Verify each message
  for (int i = 0; i < 3; i++) {
    printf("... Verifying message %d ...\n", i + 1);
    int result = verify(message_files[i], signature_files[i], pubkey);

    if (result < 0) {
      printf("Unknown authenticity of message %d\n", i + 1);
      print_file(message_files[i], CRESET);
    } else if (result == 0) {
      printf("Do not trust message %d!\n", i + 1);
      print_file(message_files[i], RED);
    } else {
      printf("Message %d is authentic!\n", i + 1);
      print_file(message_files[i], GRN);
    }
  }

  EVP_PKEY_free(pubkey);

  return 0;
}

/*
    Verify that the file `message_path` matches the signature `sign_path`
    using `pubkey`.
    Returns:
         1: Message matches signature
         0: Signature did not verify successfully
        -1: Message is does not match signature
*/
int verify(const char *message_path, const char *sign_path, EVP_PKEY *pubkey) {
#define MAX_FILE_SIZE 512
  unsigned char message[MAX_FILE_SIZE];
  unsigned char signature[MAX_FILE_SIZE];

  // TODO: Check if the message is authentic using the signature.
  // Look at: https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying

  FILE *fpMSG = fopen(message_path, "r");
  if (fpMSG == NULL) {
    return 0;
  }

  char ch;
  int i = 0;
  while ((ch = fgetc(fpMSG)) != EOF) {
    message[i] = ch;
    // printf("%c", message[i]);
    i++;
  }
  int mLen = i;
  // printf("%d\n", mLen);

  fclose(fpMSG);

  FILE *fpSIG = fopen(sign_path, "r");
  if (fpSIG == NULL) {
    return 0;
  }

  if (fgets(signature, MAX_FILE_SIZE, fpSIG) == NULL) {
    return 0;
  }
  int sLen = strlen(signature);

  fclose(fpSIG);

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  if (1 != EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey)) {
    return 0;
  }
  if (1 != EVP_DigestVerifyUpdate(ctx, message, mLen)) {
    return 0;
  }
  if (1 == EVP_DigestVerifyFinal(ctx, signature, sLen)) {
    return 1;
  } else {
    return 0;
  }

  EVP_MD_CTX_free(ctx);

  return -1;
}
