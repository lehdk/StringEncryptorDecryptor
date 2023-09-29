using System.Security.Cryptography;
using EncryptorDecryptor.Constants;

namespace EncryptorDecryptor;

internal class KeyGenerator
{
    private static readonly byte[] Salt = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 };
    
    /// <summary>
    /// Generates a cryptographic key from a provided password using PBKDF2 with SHA-512.
    /// </summary>
    /// <param name="password">The password from which to derive the key.</param>
    /// <returns>The generated key as a byte array.</returns>
    public byte[] CreateKey(string password)
    {
        var keyGenerator = new Rfc2898DeriveBytes(password, Salt, AppConstants.ITERATIONS, HashAlgorithmName.SHA512);

        return keyGenerator.GetBytes(AppConstants.KEY_BYTES);
    }
}
