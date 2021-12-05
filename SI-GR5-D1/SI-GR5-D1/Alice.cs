using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SI_GR5_D1
{
    class Alice
    {
        public static byte[] alicePublicKey;

        public static void Main(string[] args)
        {
            using (ECDiffieHellmanCng alice = new ECDiffieHellmanCng())
            {
                Console.WriteLine("=========================");

                alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                alice.HashAlgorithm = CngAlgorithm.Sha256;
                alicePublicKey = alice.PublicKey.ToByteArray();
                Console.WriteLine("\nAlice`s public key: ");
                //Console.WriteLine(Encoding.ASCII.GetString(alicePublicKey));
                Console.WriteLine(ByteArrayToString(alicePublicKey));

                Bob bob = new Bob();
                CngKey bobKey = CngKey.Import(bob.bobPublicKey, CngKeyBlobFormat.EccPublicBlob);

                byte[] aliceKey = alice.DeriveKeyMaterial(bobKey);

                Console.WriteLine("\nAlice`s generated private key , using Bob`s public key:" + ByteArrayToString(aliceKey));

                byte[] encryptedMessage = null;
                byte[] iv = null;
                
                Send(aliceKey, "Plainteksi i cili do te enkriptohet", out encryptedMessage, out iv);
                bob.Receive(encryptedMessage, iv);
                Console.ReadKey();
            }
        }

        private static void Send(byte[] key, string secretMessage, out byte[] encryptedMessage, out byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                iv = aes.IV;

                // Encrypt the message
                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plaintextMessage = Encoding.ASCII.GetBytes(secretMessage);
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    encryptedMessage = ciphertext.ToArray();
                    Console.WriteLine("\n=========================");
                    Console.WriteLine("\nPlaintext: " + secretMessage);
                    Console.WriteLine("\nCiphertext: " + ByteArrayToString(encryptedMessage));


                }
            }
        }
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
 
}
