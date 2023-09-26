using System.Security.Cryptography;

namespace EncryptorDecryptor.Security;

public sealed class Encryptor
{
    private readonly KeyGenerator _keyGenerator;

    public Encryptor()
    {
        _keyGenerator = new KeyGenerator();
    }

    public string Encrypt(string plainText, string password)
    {
        byte[] iv = new byte[16];
        byte[] array;

        using (var aes = Aes.Create())
        {
            aes.Key = _keyGenerator.CreateKey(password);
            aes.IV = iv;

            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (var streamWriter = new StreamWriter(cryptoStream))
                        streamWriter.Write(plainText);

                    array = memoryStream.ToArray();
                }
            }
        }

        return Convert.ToBase64String(array);
    }
}
