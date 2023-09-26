using System.Security.Cryptography;

namespace EncryptorDecryptor;

public sealed class Decryptor
{
    private readonly KeyGenerator _keyGenerator;

    public Decryptor()
    {
        _keyGenerator = new KeyGenerator();
    }

    public string Decrypt(string cipher, string password)
    {
        byte[] iv = new byte[16];
        byte[] buffer = Convert.FromBase64String(cipher);

        using (var aes = Aes.Create())
        {
            aes.Key = _keyGenerator.CreateKey(password);
            aes.IV = iv;
            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (var memoryStream = new MemoryStream(buffer))
            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            using (var streamReader = new StreamReader(cryptoStream))
                return streamReader.ReadToEnd();
        }
    }
}
