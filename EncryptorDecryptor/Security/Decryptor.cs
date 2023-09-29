using System.Security.Cryptography;
using EncryptorDecryptor.Constants;

namespace EncryptorDecryptor;

public sealed class Decryptor
{
    private readonly KeyGenerator _keyGenerator;

    public Decryptor()
    {
        _keyGenerator = new KeyGenerator();
    }
    /// <summary>
    /// Decrypts a cipher text using the provided password.
    /// </summary>
    /// <param name="cipher">The cipher text to decrypt, in Base64.</param>
    /// <param name="password">The password used for decryption.</param>
    /// <returns>The decrypted plaintext as a string.</returns>
    public string Decrypt(string cipher, string password)
    {
        byte[] buffer = Convert.FromBase64String(cipher);

        var iv = new byte[AppConstants.INITIALIZATION_VECTOR_BYTE_SIZE];
        Array.Copy(buffer, 0, iv, 0, AppConstants.INITIALIZATION_VECTOR_BYTE_SIZE);

        var cipherBytes = new byte[buffer.Length - AppConstants.INITIALIZATION_VECTOR_BYTE_SIZE];
        Array.Copy(buffer, AppConstants.INITIALIZATION_VECTOR_BYTE_SIZE, cipherBytes, 0, cipherBytes.Length);

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
