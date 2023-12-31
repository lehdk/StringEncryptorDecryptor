﻿using EncryptorDecryptor.Security;

namespace EncryptorDecryptor;

public sealed class Program
{
    public static void Main(string[] args)
    {
        Console.Write("Please enter a password: ");
        string password = ReadPasswordMasked();
        Console.WriteLine("Do you want to\n" +
            "0) Exit\n" +
            "1) Encrypt\n" +
            "2) Decrypt");

        string option = string.Empty;

        do
        {
            string input = Console.ReadLine() ?? string.Empty;
            
            switch (input)
            {
                case "0":
                case "1": // Encryot
                case "2": // Decrypt
                    option = input;
                    break;
                default:
                    break;
            }
        } while(option == string.Empty);

        if (option == "0")
            return;

        if(option == "1") // Encrypt
        {
            Console.WriteLine("Enter the message you want to encrypt: ");
            string toEncrypt = Console.ReadLine() ?? string.Empty;

            var encryptor = new Encryptor();
            var result = encryptor.Encrypt(toEncrypt, password);

            string path = Path.GetFullPath("Encrypted.txt");

            using (var output = new StreamWriter(path))
            {
                output.Write(result);
            }

            Console.WriteLine($"File written to\n{path}");

        } else // Decrypt
        {
            Console.WriteLine("Please give the path to the file you want to decrypt");
            string? path = Console.ReadLine();
            ArgumentNullException.ThrowIfNullOrEmpty(path);

            if (!File.Exists(path))
            {
                Console.WriteLine("File not found!");
                return;
            }

            string cipher = File.ReadAllText(path);
            var decrypter = new Decryptor();

            try
            {
                var result = decrypter.Decrypt(cipher, password);
                Console.WriteLine("The decrypted message:\n" + result);
            } catch(Exception)
            {
                Console.WriteLine("Wrong password!");
            }
        }
    }

    /// <summary>
    /// Reads a password from the console and masks the letters typed with an *
    /// </summary>
    /// <returns>Returns the password typed in by the user as plain text</returns>
    public static string ReadPasswordMasked()
    {
        string password = string.Empty;
        ConsoleKeyInfo keyInfo;

        do
        {
            keyInfo = Console.ReadKey(true);

            if (keyInfo.Key == ConsoleKey.Enter)
                continue;

            if(keyInfo.Key == ConsoleKey.Backspace)
            {
                if (password.Length == 0)
                    continue;

                password = password.Substring(0, password.Length - 1);
                Console.Write("\b \b");
            } else
            {
                password += keyInfo.KeyChar;
                Console.Write("*");
            }
        } while (keyInfo.Key != ConsoleKey.Enter);

        Console.WriteLine();

        return password;
    }    
}