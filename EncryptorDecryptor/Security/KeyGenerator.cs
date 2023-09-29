using System.Security.Cryptography;
using EncryptorDecryptor.Constants;

namespace EncryptorDecryptor;

internal class KeyGenerator
{
    private static readonly byte[] Salt = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 };
    public byte[] CreateKey(string password)
    {
        const int Iterations = 300;
        var keyGenerator = new Rfc2898DeriveBytes(password, Salt, Iterations, HashAlgorithmName.SHA512);

        return keyGenerator.GetBytes(AppConstants.KEY_BYTES);
    }
}
