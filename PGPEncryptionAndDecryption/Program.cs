using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;

namespace PGPEncryptionAndDecryption
{
    class Program
    {
        static void Main(string[] args)
        {
              EncryptDecrypt.DecryptFile(
                       @"C:\Users\sallal\source\repos\PGPEncryptionAndDecryption\PGPEncryptionAndDecryption\encrypted.pgp",
                       @"C:\Users\sallal\source\repos\PGPEncryptionAndDecryption\PGPEncryptionAndDecryption\0x88119E66-sec.asc",
                       "password",
                       @"C:\Users\sallal\source\repos\PGPEncryptionAndDecryption\PGPEncryptionAndDecryption\decrypted.txt");
                
            
         


            EncryptDecrypt.EncryptFile(
              @"C:\Users\sallal\source\repos\PGPEncryptionAndDecryption\PGPEncryptionAndDecryption\encrypted.pgp",
              @"C:\Users\sallal\source\repos\PGPEncryptionAndDecryption\PGPEncryptionAndDecryption\plaintext.txt",
              @"C:\Users\sallal\source\repos\PGPEncryptionAndDecryption\PGPEncryptionAndDecryption\0x88119E66-pub.asc", true, true);



           


        }
       
    }
}