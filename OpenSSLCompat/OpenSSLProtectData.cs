using System;
using System.Security.Cryptography;
using System.Text;

namespace OpenSSLCompat
{
    // intended to be used with openssl
    // encrypt command: openssl enc -aes-256-cbc -e -base64 -A -md sha256 -salt -in <(echo -n "$plainText")  -pass file:<(echo -n "$passphrase")
    // decrypt command: openssl enc -aes-256-cbc -d -base64 -A -md sha256       -in <(echo "$encryptedText") -pass file:<(echo -n "$passphrase")

    // NOTES about OpenSslCompatDeriveBytes, tldr; use high entropy passphrase
    // https://security.stackexchange.com/questions/29106/openssl-recover-key-and-iv-by-passphrase
    public class OpenSSLProtectData
    {
        private const String HASH_ALGORITHM = "SHA256";
        private const String OPENSSL_SALT_PREFIX = "Salted__";
        private static readonly byte[] OPENSSL_SALT_PREFIX_BYTES = Encoding.ASCII.GetBytes(OPENSSL_SALT_PREFIX);
        private static readonly Encoding DEFAULT_ENCODING = new UTF8Encoding(false, true);

        private readonly Encoding m_Encoding;
        private readonly RNGCryptoServiceProvider m_RngCrypto;

        public OpenSSLProtectData(RNGCryptoServiceProvider rngCrypto)
            : this(DEFAULT_ENCODING, rngCrypto)
        {
        }

        public OpenSSLProtectData(Encoding encoding, RNGCryptoServiceProvider rngCrypto)
        {
            m_Encoding = encoding;
            m_RngCrypto = rngCrypto;
        }

        public String Encrypt(String data, String secret)
        {
            var encryptedBytes = Encrypt(m_Encoding.GetBytes(data), m_Encoding.GetBytes(secret));
            return Convert.ToBase64String(encryptedBytes);
        }

        public String Decrypt(String base64Encrypted, String secret)
        {
            var unencryptdBytes = Decrypt(Convert.FromBase64String(base64Encrypted), m_Encoding.GetBytes(secret));
            return m_Encoding.GetString(unencryptdBytes);
        }

        public byte[] Encrypt(byte[] data, byte[] secret)
        {
            // AesManaged: native .NET, likely preferred for smaller buffers
            // AesCryptoServiceProvider: FIPS compliance, but probably only Windows available?
            // Aes.Create allows framework to choose most appropriate implementation
            using (var aesAlgorithm = Aes.Create())
            {
                var saltBytes = new byte[8];
                m_RngCrypto.GetNonZeroBytes(saltBytes);

                using (var deriveBytes = new OpenSslCompatDeriveBytes(secret, saltBytes, HASH_ALGORITHM, 1))
                {
                    var bytes = deriveBytes.GetBytes(48);
                    byte[] key = new byte[32],
                           iv = new byte[16];
                    Buffer.BlockCopy(bytes, 0, key, 0, key.Length);
                    Buffer.BlockCopy(bytes, key.Length, iv, 0, iv.Length);

                    //DeriveKeyAndIV(secret, saltBytes, HASH_ALGORITHM, 1, out var key, out var iv);

                    aesAlgorithm.BlockSize = 128;
                    aesAlgorithm.KeySize = 256;
                    aesAlgorithm.Key = key;
                    aesAlgorithm.IV = iv;
                    aesAlgorithm.Mode = CipherMode.CBC;
                    aesAlgorithm.Padding = PaddingMode.PKCS7;

                    using (var encryptor = aesAlgorithm.CreateEncryptor())
                    {
                            Console.WriteLine(data.Length);
                        var encryptedBytes = encryptor.TransformFinalBlock(data, 0, data.Length);
                        var encryptedWithSaltBytes = new byte[OPENSSL_SALT_PREFIX_BYTES.Length + saltBytes.Length + encryptedBytes.Length];

                        Buffer.BlockCopy(OPENSSL_SALT_PREFIX_BYTES, 0, encryptedWithSaltBytes, 0, OPENSSL_SALT_PREFIX_BYTES.Length);
                        Buffer.BlockCopy(saltBytes, 0, encryptedWithSaltBytes, OPENSSL_SALT_PREFIX_BYTES.Length, saltBytes.Length);
                        Buffer.BlockCopy(encryptedBytes, 0, encryptedWithSaltBytes, OPENSSL_SALT_PREFIX_BYTES.Length + saltBytes.Length, encryptedBytes.Length);

                        return encryptedWithSaltBytes;
                    }
                }
            }
        }

        public byte[] Decrypt(byte[] encrypted, byte[] secret)
        {
            using (var aesAlgorithm = new AesManaged())
            {
                var discoveredSalt = new byte[8];
                var encryptedWithSaltBytes = encrypted;
                var encryptedBytes = new byte[encryptedWithSaltBytes.Length - OPENSSL_SALT_PREFIX_BYTES.Length - discoveredSalt.Length];

                Buffer.BlockCopy(encryptedWithSaltBytes, OPENSSL_SALT_PREFIX_BYTES.Length, discoveredSalt, 0, discoveredSalt.Length);
                Buffer.BlockCopy(encryptedWithSaltBytes, OPENSSL_SALT_PREFIX_BYTES.Length + discoveredSalt.Length, encryptedBytes, 0, encryptedBytes.Length);

                using (var deriveBytes = new OpenSslCompatDeriveBytes(secret, discoveredSalt, HASH_ALGORITHM, 1))
                {
                    var bytes = deriveBytes.GetBytes(48);
                    byte[] key = new byte[32],
                           iv = new byte[16];
                    Buffer.BlockCopy(bytes, 0, key, 0, key.Length);
                    Buffer.BlockCopy(bytes, key.Length, iv, 0, iv.Length);

                    aesAlgorithm.Mode = CipherMode.CBC;
                    aesAlgorithm.KeySize = 256;
                    aesAlgorithm.BlockSize = 128;
                    aesAlgorithm.Padding = PaddingMode.PKCS7;
                    aesAlgorithm.Key = key;
                    aesAlgorithm.IV = iv;

                    using (var decryptor = aesAlgorithm.CreateDecryptor())
                    {
                        var plainTextBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

                        return plainTextBytes;
                    }
                }
            }
        }

        // same implmentation as OpenSslCompatDeriveBytes but threadsafe
        /*
        private static void DeriveKeyAndIV(byte[] data, byte[] salt, String hashName, int count, out byte[] key, out byte[] iv)
        {
            List<byte> hashList = new List<byte>();
            byte[] currentHash = new byte[0];

            int preHashLength = data.Length + ((salt != null) ? salt.Length : 0);
            byte[] preHash = new byte[preHashLength];

            Buffer.BlockCopy(data, 0, preHash, 0, data.Length);
            if (salt != null)
            {
                Buffer.BlockCopy(salt, 0, preHash, data.Length, salt.Length);
            }

            var hash = HashAlgorithm.Create(hashName);
            currentHash = hash.ComputeHash(preHash);

            for (int i = 1; i < count; i++)
            {
                currentHash = hash.ComputeHash(currentHash);
            }

            hashList.AddRange(currentHash);

            while (hashList.Count < 48) // for 32-byte key and 16-byte iv
            {
                preHashLength = currentHash.Length + data.Length + ((salt != null) ? salt.Length : 0);
                preHash = new byte[preHashLength];

                Buffer.BlockCopy(currentHash, 0, preHash, 0, currentHash.Length);
                Buffer.BlockCopy(data, 0, preHash, currentHash.Length, data.Length);
                if (salt != null)
                {
                    Buffer.BlockCopy(salt, 0, preHash, currentHash.Length + data.Length, salt.Length);
                }

                currentHash = hash.ComputeHash(preHash);

                for (int i = 1; i < count; i++)
                {
                    currentHash = hash.ComputeHash(currentHash);
                }

                hashList.AddRange(currentHash);
            }
            hash.Clear();
            key = new byte[32];
            iv = new byte[16];
            hashList.CopyTo(0, key, 0, 32);
            hashList.CopyTo(32, iv, 0, 16);
        }
        */
    }
}
