#include <QCoreApplication>
#include <QDebug>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <iostream>
#include <QFile>
#include <cstring>
#include <QDataStream>


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

void handleErrors(void);


void fun_write(unsigned char ciphertext[100000])
{
//    //write to file

//            QFile file("D:\\test.bin");
//            if (file.open(QIODevice::WriteOnly)) {
//                file.write(reinterpret_cast<char *>(&ciphertext), sizeof(ciphertext));
//                file.close();
//            }

//            //read from file
//            QFile inFile("D:\\testb.bin");
//            const QByteArray in = inFile.readAll();
//            inFile.close();

//            std::memcpy(ciphertext,in.constData(),in.size());
    QFile file("D:\\test.txt");
    if(!file.open(QIODevice::WriteOnly)){
        qDebug() << "error opening!" << endl;
        return;
    }

    QDataStream out(&file);
    out.setVersion(QDataStream::Qt_4_9);
    for (int i = 0; i < 100000; ++i) {
        out << ciphertext[i];
    }
//    out << ciphertext;

    file.flush();
    file.close();
}


QByteArray fun_read()
{
    //    //write to file

    //            QFile file("D:\\test.bin");
    //            if (file.open(QIODevice::WriteOnly)) {
    //                file.write(reinterpret_cast<char *>(&ciphertext), sizeof(ciphertext));
    //                file.close();
    //            }

    //            //read from file
    //            QFile inFile("D:\\testb.bin");
    //            const QByteArray in = inFile.readAll();
    //            inFile.close();

    //            std::memcpy(ciphertext,in.constData(),in.size());
        QFile file("D:\\test.txt");
        if(!file.open(QIODevice::ReadOnly)){
            qDebug() << "error opening!" << endl;
            return NULL;
        }

        QDataStream in(&file);
        in.setVersion(QDataStream::Qt_4_9);

        QByteArray iContents = file.readAll();

        unsigned char* arr = new unsigned char[100000];

        std::memcpy(arr,iContents.constData(),iContents.size());

    //    out << ciphertext;
//        for (int i = 0; i < 100000; ++i) {
//            arr[i] = (unsigned char)iContents[i];
//            qDebug() << arr[i] << ' ' << iContents[i] << endl;
//        }

//        file.flush();
        file.close();
        return iContents;
}



int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    /* Set up the key and iv. Do I need to say to not hard code these in a
       * real application? :-)
       */

      /* A 256 bit key */
      unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

      /* A 128 bit IV */
      unsigned char *iv = (unsigned char *)"0123456789012345";

      /* Message to be encrypted */


      unsigned char *plaintext =
                    (unsigned char *)"This is a test of openssl encryption decryption";



      /* Buffer for ciphertext. Ensure the buffer is long enough for the
       * ciphertext which may be longer than the plaintext, dependant on the
       * algorithm and mode
       */
      unsigned char ciphertext[100000];

      /* Buffer for the decrypted text */
      unsigned char decryptedtext[100000];

      int decryptedtext_len, ciphertext_len;

      /* Encrypt the plaintext */
        ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                                  ciphertext);





//        fun_write(ciphertext);
        fun_read();
        /* Do something useful with the ciphertext here */
        printf("Ciphertext is:\n");
//        std::cout << ciphertext << std::endl;
        printf("%s\n", ciphertext);
//        BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
        //print cipher text
        const char * cipher = (const char *) ciphertext;
        QString str = QString::fromUtf8(cipher, ciphertext_len);
        qDebug() << str << endl;
        //-----------------Base64 Encode--------------------------------
        printf("\n");
        char encodedData[100];
        EVP_EncodeBlock((unsigned char *)encodedData, ciphertext, 16);
        printf("Base64 Encode Data: ");
        printf(encodedData);
        printf("\n");
        //---------------------------------------------------------------

        QByteArray arr= fun_read();
        unsigned char c[100000];
        std::memcpy(c,arr.constData(),arr.size());
        /* Decrypt the ciphertext */
        decryptedtext_len = decrypt(c, ciphertext_len, key, iv,
          decryptedtext);

//        std::cout << "decrypted: " << decryptedtext << std::endl;
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);



    return a.exec();
}


void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}
