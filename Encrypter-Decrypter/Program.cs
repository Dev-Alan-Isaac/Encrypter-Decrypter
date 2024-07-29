using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    // Key and IV for AES encryption
    // It's crucial to use the same key and IV for both encryption and decryption
    private static readonly byte[] Key = Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");
    private static readonly byte[] IV = Encoding.UTF8.GetBytes("abcdef9876543210");

    static void Main()
    {
        Console.WriteLine("Welcome to Text Encryptor/Decryptor!");
        bool continueLoop = true;

        while (continueLoop)
        {
            Console.WriteLine("1. Encrypt text");
            Console.WriteLine("2. Decrypt text");
            Console.WriteLine("3. Exit");
            Console.Write("Enter your choice (1, 2, or 3): ");

            var choice = Console.ReadLine();
            switch (choice)
            {
                case "1":
                    Console.Write("Enter the text to encrypt: ");
                    var plainText = Console.ReadLine();
                    var encryptedText = Encrypt(plainText);
                    Console.WriteLine($"Encrypted text: {encryptedText}");
                    break;

                case "2":
                    Console.Write("Enter the encrypted text: ");
                    var cipherText = Console.ReadLine();
                    var decryptedText = Decrypt(cipherText);
                    Console.WriteLine($"Decrypted text: {decryptedText}");
                    break;

                case "3":
                    continueLoop = false;
                    Console.WriteLine("Goodbye! Ride safe.");
                    break;

                default:
                    Console.WriteLine("Invalid choice. Please enter 1, 2, or 3.");
                    break;
            }
        }
    }

    static string Encrypt(string plainText)
    {
        // Check input
        if (string.IsNullOrEmpty(plainText))
            throw new ArgumentNullException(nameof(plainText), "Plaintext cannot be null or empty.");

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;
            aesAlg.Padding = PaddingMode.PKCS7; // Padding mode

            // Create an encryptor
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    byte[] encrypted = msEncrypt.ToArray();
                    return Convert.ToBase64String(encrypted);
                }
            }
        }
    }

    static string Decrypt(string cipherText)
    {
        // Check input
        if (string.IsNullOrEmpty(cipherText))
            throw new ArgumentNullException(nameof(cipherText), "Ciphertext cannot be null or empty.");

        byte[] cipherBytes = Convert.FromBase64String(cipherText);

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;
            aesAlg.Padding = PaddingMode.PKCS7; // Padding mode

            // Create a decryptor
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }
}
