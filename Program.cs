using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;


namespace P3
{
    class Program
    {
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte [] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            
            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
        static void Main(string[] args)
        {
            string[] theGoods = Environment.GetCommandLineArgs();

            string hexylady = theGoods[1];
            string nospace = hexylady.Replace(" ", "");
            BigInteger biggy = BigInteger.Parse(nospace, System.Globalization.NumberStyles.HexNumber);
            byte[] tempIV = biggy.ToByteArray();
            Array.Reverse(tempIV);

            int N_e = Int32.Parse(theGoods[4]);
            int N_c = Int32.Parse(theGoods[5]);
            BigInteger N = BigInteger.Pow(2, N_e) - N_c;

            string g_y = theGoods[7];
            BigInteger GtotheY = 0;
            GtotheY = BigInteger.Parse(g_y);

            int x = Int32.Parse(theGoods[6]);
            BigInteger KeyBigInt = BigInteger.ModPow(GtotheY, x, N);
            byte[] Key = KeyBigInt.ToByteArray();
            string KeyBytes = BitConverter.ToString(Key).Replace("-", "");

            string cipherT = theGoods[8];
            string spaceless = cipherT.Replace(" ", "");
            BigInteger bigCi = BigInteger.Parse(spaceless, System.Globalization.NumberStyles.HexNumber);
            byte[] tempcipherText = bigCi.ToByteArray();
            Array.Reverse(tempcipherText);

            string pText = theGoods[9];

            using (Aes myAes = Aes.Create())
            {
                myAes.Key = Key;
                myAes.IV = tempIV;
                string plainText = pText;
                byte[] cipherText = tempcipherText;

                byte[] encrypted = EncryptStringToBytes_Aes(plainText, myAes.Key, myAes.IV);
                string encryptedS = BitConverter.ToString(encrypted).Replace("-", " ");
                encryptedS = encryptedS.Trim();
                
                string decrypted = DecryptStringFromBytes_Aes(cipherText, myAes.Key, myAes.IV);
                decrypted = decrypted.Trim();
                
                Console.WriteLine("{0},{1}", decrypted.Replace("\x03", ""), encryptedS);
            }
        }
    }
}
