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
        byte[] buffer = Convert.FromBase64String(cipher);

        var iv = new byte[16];
        Array.Copy(buffer, 0, iv, 0, 16);

        var cipherBytes = new byte[buffer.Length - 16];
        Array.Copy(buffer, 16, cipherBytes, 0, cipherBytes.Length);

        using (var aes = Aes.Create())
        {
            aes.Key = _keyGenerator.CreateKey(password);
            aes.IV = iv;
            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (var memoryStream = new MemoryStream(cipherBytes))
            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            using (var streamReader = new StreamReader(cryptoStream))
                return streamReader.ReadToEnd();
        }
    }
}
