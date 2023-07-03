using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PGPEncryptionAndDecryption
{

    // Encrypt a file using PGP decryption 
  public class EncryptDecrypt
    {
        public static void EncryptFile(
            string outputFileName,
            string inputFileName,
            string encKeyFileName,
            bool armor,
            bool withIntegrityCheck)
        {
            PgpPublicKey encKey = PgpExampleUtilities.ReadPublicKey(encKeyFileName);

            using (Stream output = File.Create(outputFileName))
            {
                EncryptFile(output, inputFileName, encKey, armor, withIntegrityCheck);
            }
        }

     

        private static void EncryptFile(
            Stream outputStream,
            string fileName,
            PgpPublicKey encKey,
            bool armor,
            bool withIntegrityCheck)
        {
            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            try
            {
                byte[] bytes = PgpExampleUtilities.CompressFile(fileName, CompressionAlgorithmTag.Zip);

                PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(
                    SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                encGen.AddMethod(encKey);

                Stream cOut = encGen.Open(outputStream, bytes.Length);

                cOut.Write(bytes, 0, bytes.Length);
                cOut.Close();

                if (armor)
                {
                    outputStream.Close();
                }
            }
            catch (PgpException e)
            {
                Console.Error.WriteLine(e);

                Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {
                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);
                }
            }
        }

        public class PgpExampleUtilities
        {
            internal static PgpPublicKey ReadPublicKey(string fileName)
            {
                using (Stream keyIn = File.OpenRead(fileName))
                {
                    return ReadPublicKey(keyIn);
                }
            }

            internal static PgpPublicKey ReadPublicKey(Stream input)
            {
                PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(
                    PgpUtilities.GetDecoderStream(input));

                foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {
                        if (key.IsEncryptionKey)
                        {
                            return key;
                        }
                    }
                }

                throw new ArgumentException("Can't find encryption key in key ring.");
            }

            internal static byte[] CompressFile(string fileName, CompressionAlgorithmTag algorithm)
            {
                MemoryStream bOut = new MemoryStream();
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(algorithm);
                PgpUtilities.WriteFileToLiteralData(comData.Open(bOut), PgpLiteralData.Binary, new FileInfo(fileName));
                comData.Close();
                return bOut.ToArray();
            }

           
        }






        /* --------------------------------------------------------------------------------------------------------------- */






        // Decrypt a file using PGP decryption 
       
       public static void DecryptFile(string inputFilePath, string privateKeyFilePath, string privateKeyPassword, string outputFilePath)
        {
            using (Stream inputStream = File.OpenRead(inputFilePath))
            using (Stream privateKeyStream = File.OpenRead(privateKeyFilePath))
            using (Stream outputStream = File.Create(outputFilePath))
            {
                PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                PgpEncryptedDataList encDataList = null;
                PgpObject pgpObject = pgpFactory.NextPgpObject();

                while (pgpObject != null)
                {
                    if (pgpObject is PgpEncryptedDataList)
                    {
                        encDataList = (PgpEncryptedDataList)pgpObject;
                        break;
                    }

                    pgpObject = pgpFactory.NextPgpObject();
                }

                if (encDataList != null)
                {
                    PgpPrivateKey privateKey = GetPrivateKey(privateKeyStream, privateKeyPassword);
                    PgpPublicKeyEncryptedData encData = encDataList.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().FirstOrDefault();

                    if (encData != null)
                    {
                        using (Stream decryptedStream = encData.GetDataStream(privateKey))
                        {
                            PgpObjectFactory plainFactory = new PgpObjectFactory(decryptedStream);
                            PgpObject message = plainFactory.NextPgpObject();

                            if (message is PgpCompressedData compressedData)
                            {
                                PgpObjectFactory compressedFactory = new PgpObjectFactory(compressedData.GetDataStream());
                                message = compressedFactory.NextPgpObject();
                            }

                            if (message is PgpLiteralData literalData)
                            {
                                Stream literalDataStream = literalData.GetInputStream();
                                literalDataStream.CopyTo(outputStream);
                            }
                            else if (message is PgpOnePassSignatureList)
                            {
                                throw new PgpException("Encrypted message contains a signed message - not literal data.");
                            }
                            else
                            {
                                throw new PgpException("Message is not a simple encrypted file - type unknown.");
                            }
                        }
                    }
                    else
                    {
                        throw new PgpException("No encrypted data found in the input file.");
                    }
                }
                else
                {
                    throw new PgpException("Input file does not contain encrypted data.");
                }
            }
        }


        private static PgpPrivateKey GetPrivateKey(Stream privateKeyStream, string privateKeyPassword)
        {
            PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
            PgpSecretKey secretKey = GetFirstSecretKey(secretKeyRingBundle);

            if (secretKey != null)
            {
                PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(privateKeyPassword.ToCharArray());
                if (privateKey != null)
                {
                    return privateKey;
                }
            }

            throw new ArgumentException("No private key found in the key ring.");
        }

        private static PgpSecretKey GetFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {
            foreach (PgpSecretKeyRing keyRing in secretKeyRingBundle.GetKeyRings())
            {
                foreach (PgpSecretKey secretKey in keyRing.GetSecretKeys())
                {
                    if (secretKey.IsSigningKey)
                    {
                        return secretKey;
                    }
                }
            }

            return null;
        }
    
    }


}


