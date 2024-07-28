using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
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
        using var aesAlg = Aes.Create();
        aesAlg.GenerateKey();
        aesAlg.GenerateIV();

        var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
        var memoryStream = new MemoryStream();
        using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
        using (var streamWriter = new StreamWriter(cryptoStream))
        {
            streamWriter.Write(plainText);
        }

        var encryptedBytes = memoryStream.ToArray();
        return Convert.ToBase64String(encryptedBytes);
    }

    static string Decrypt(string cipherText)
    {
        using var aesAlg = Aes.Create();
        aesAlg.GenerateKey(); // Use the same key as during encryption
        aesAlg.GenerateIV(); // Use the same IV as during encryption

        var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        var encryptedBytes = Convert.FromBase64String(cipherText);
        using var memoryStream = new MemoryStream(encryptedBytes);
        using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        using var streamReader = new StreamReader(cryptoStream);

        return streamReader.ReadToEnd();
    }
}