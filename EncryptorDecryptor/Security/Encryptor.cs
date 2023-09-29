using System.Security.Cryptography;

namespace EncryptorDecryptor.Security;

public sealed class Encryptor
{
    private readonly KeyGenerator _keyGenerator;
    private readonly Random _random;

    public Encryptor()
    {
        _keyGenerator = new KeyGenerator();
        _random = new Random();
    }

    public string Encrypt(string plainText, string password)
    {
        byte[] iv = new byte[16];
        _random.NextBytes(iv);

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

        var res = iv.Concat(array).ToArray();

        return Convert.ToBase64String(res);
    }
}
