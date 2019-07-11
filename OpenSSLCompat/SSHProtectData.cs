using System;
using System.Security.Cryptography;
using System.Text;

namespace OpenSSLCompat
{
    // creates random symmetric key for each usage
    // symmetric key is used with underlying encryption standard as passphrase (AES in our case)
    // key is then encrypted with public key information

    // intended to be used with openssl
    // encryption:
    // openssl rand -out symmetric.key 32
    // openssl enc -aes-256-cbc -e -base64 -A -md sha256 -salt -in <(echo -n "$plainText") -pass file:symmetric.key
    // openssl rsautl -encrypt -oaep -pubin -inkey <(ssh-keygen -e -f ~/.ssh/id_rsa.pub -m PKCS8) -in symmetric.key -out symmetric.key.enc
    //
    // decryption
    // openssl rsautl -decrypt -oaep -inkey ~/.ssh/id_rsa -in symmetric.key.enc -out symmetric.key
    // openssl enc -aes-256-cbc -d -base64 -A -md sha256 -in <(echo "$encryptedText") -pass file:symmetric.key
    public class SSHProtectData
    {
        private static readonly Encoding DEFAULT_ENCODING = new UTF8Encoding(false, true);

        private readonly Encoding m_Encoding;
        private readonly RNGCryptoServiceProvider m_RngCrypto;
        private readonly OpenSSLProtectData m_Encryption;

        public SSHProtectData(RNGCryptoServiceProvider rngCrypto, OpenSSLProtectData encryption)
            : this(DEFAULT_ENCODING, rngCrypto, encryption)
        {
        }

        public SSHProtectData(Encoding encoding, RNGCryptoServiceProvider rngCrypto, OpenSSLProtectData encryption)
        {
            m_Encoding = encoding;
            m_RngCrypto = rngCrypto;
            m_Encryption = encryption;
        }

        public (String EncryptedText, byte[] SymmetricKey, byte[] EncryptedKey) Encrypt(String plainText, RSAParameters publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);
                var symmetricKey = new byte[32];
                m_RngCrypto.GetNonZeroBytes(symmetricKey);

                var encryptedBytes = m_Encryption.Encrypt(m_Encoding.GetBytes(plainText), symmetricKey);
                var encryptedKey = rsa.Encrypt(symmetricKey, RSAEncryptionPadding.OaepSHA1);

                return (Convert.ToBase64String(encryptedBytes), symmetricKey, encryptedKey);
            }
        }

        public byte[] EncryptSymmetricKey(byte[] symmetricKey, RSAParameters publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);

                var encryptedKey = rsa.Encrypt(symmetricKey, RSAEncryptionPadding.OaepSHA1);

                return encryptedKey;
            }
        }

        // previously used symmetricKey
        public String EncryptWithKey(String plainText, byte[] symmetricKey)
        {
            var encryptedBytes = m_Encryption.Encrypt(m_Encoding.GetBytes(plainText), symmetricKey);
            return Convert.ToBase64String(encryptedBytes);
        }

        // EncryptedText is base64 encoded
        public String Decrypt(String encryptedText, byte[] encryptedKey, RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);
                var symmetricKey = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA1);
                var encryptedBytes = Convert.FromBase64String(encryptedText);

                var unencryptedBytes = m_Encryption.Decrypt(encryptedBytes, symmetricKey);
                return m_Encoding.GetString(unencryptedBytes);
            }
        }
    }
}
