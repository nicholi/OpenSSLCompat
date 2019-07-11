using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace OpenSSLCompat
{
    class Program
    {
        static void Main(string[] args)
        {
            // setup
            var rng = new RNGCryptoServiceProvider();
            var sslProtect = new OpenSSLProtectData(rng);
            var sshProtect = new SSHProtectData(rng, sslProtect);

            // generate SSH keypair
            var keyPair = OpenSSHKeygen.GenerateKeyPair();

            // generate single 32 byte key for aes
            var symmetricKey = new byte[32];
            rng.GetNonZeroBytes(symmetricKey);

            // some random json string
            var plainText = "{\"id\":\"some_id\",\"debugging\":false,\"redis\":{\"host\":\"localhost\",\"port\":6379,\"password\":\"passy\",\"db\":0,\"channelPrefix\":null},\"http\":{\"port\":8080},\"ws\":{\"keepalive\":true,\"keepaliveInterval\":30000},\"clientId\":\"some_id\",\"clientSecret\":\"some_secret\"}";

            // flip this to use the same symmetricKey (generated above)
            // or generate a new symmetric key every time
            // when the same key is used there doesn't seem to be any problems
            bool useSameKey = false;

            // loop multiple encryptions and count failures
            var failures = 0;
            for (var i = 0; i < 50; i++)
            {
                if (!EncryptDecrypt(sshProtect, keyPair, plainText, useSameKey ? symmetricKey : null))
                {
                    failures++;
                }
            }
            Console.WriteLine($"Total Failures: {failures}");
        }

        // encrypt with C#
        // attempt decrypt with openssl command-line process
        static bool EncryptDecrypt(SSHProtectData sshProtect, RSAParameters keyPair, String plainText, byte[] symmetricKey)
        {
            // separate publicKey components
            var publicKey = new RSAParameters()
                {
                    Exponent = keyPair.Exponent,
                    Modulus = keyPair.Modulus
                };

            String encryptedText;
            byte[] encryptedKey;
            if (symmetricKey == null)
            {
                // produce a new symmetricKey each time
                // plainText is encrypted with symmetricKey via AES. resulting encryptedText is base64 encoded
                // symmetricKey is encrypted via RSA with publicKey, producing encryptedKey
                (encryptedText, symmetricKey, encryptedKey) = sshProtect.Encrypt(plainText, publicKey);
            }
            else
            {
                // same process as above except using provided symmetricKey instead of generating new one
                encryptedKey = sshProtect.EncryptSymmetricKey(symmetricKey, keyPair);
                encryptedText = sshProtect.EncryptWithKey(plainText, symmetricKey);
            }

            /*
            Console.WriteLine("\n\n\n\n");
            Console.WriteLine($"PlainText: {plainText}\nEncryptedText: {encryptedText}");
            Console.WriteLine($"SymmetricKey: {Convert.ToBase64String(symmetricKey)}");
            Console.WriteLine($"EncryptedKey: {Convert.ToBase64String(encryptedKey)}");
            Console.WriteLine("\n\n\n\n");
            */

            // writing all files to tmp files for easy usage in openssl cli

            // write SSH private key for openssl input
            var privateKeyFile = Path.GetTempFileName();
            File.WriteAllText(privateKeyFile, OpenSSHKeygen.ExportPrivateKeyPKCS1(keyPair));

            // write encryptedKey for openssl input
            var encryptedKeyFile = Path.GetTempFileName();
            using (var writer = new BinaryWriter(File.Open(encryptedKeyFile, FileMode.Open)))
            {
                writer.Write(encryptedKey, 0, encryptedKey.Length);
            }

            // write encryptedText for openssl input
            var encryptedTextFile = Path.GetTempFileName();
            File.WriteAllText(encryptedTextFile, encryptedText);

            var (symmetricKeyFile, decryptKeyCmd) = DecryptSymmetricKeyWithOpenSSL(privateKeyFile, encryptedKeyFile);
            var (plainTextFile, decryptTextCmd) = DecryptTextWithOpenSSL(encryptedTextFile, symmetricKeyFile);

            var encryptionSuccess = String.Equals(File.ReadAllText(plainTextFile), plainText);
            if (!encryptionSuccess)
            {
                Console.WriteLine("!!!!FAILED!!!!");
                Console.WriteLine($"Ran: {decryptKeyCmd}");
                Console.WriteLine($"Ran: {decryptTextCmd}");

                // attempt to decrypt the with C# methods
                var csharpPlainText = sshProtect.Decrypt(encryptedText, encryptedKey, keyPair);
                if (!String.Equals(csharpPlainText, plainText))
                {
                    // never happens
                    Console.WriteLine("C# failed to decrypt");
                }

                // test the raw symmetric key we used to encrypt data in C#
                // against the symmetric key obtained when openssl decrypted the key
                using (var reader = new BinaryReader(File.Open(symmetricKeyFile, FileMode.Open)))
                {
                    var symmetricBytes = new List<byte>(symmetricKey.Length);
                    while (reader.BaseStream.Position < reader.BaseStream.Length)
                    {
                        symmetricBytes.Add(reader.ReadByte());
                    }
                    if (!symmetricBytes.SequenceEqual(symmetricKey))
                    {
                        Console.WriteLine("The keys don't match!!");
                    }
                    // if the above never fires, that means the symmetric key is coming through a-ok
                }
            }

            return encryptionSuccess;
        }

        public static String RunSimpleProcess(String fileName, String arguments, String consolePrefix)
        {
            using (var proc = new Process())
            {
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.CreateNoWindow = true;

                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;

                proc.OutputDataReceived += (sender, data) =>
                {
                    //Console.WriteLine($"{consolePrefix}:stdout:{data.Data}");
                };
                proc.ErrorDataReceived += (sender, data) =>
                {
                    //Console.WriteLine($"{consolePrefix}:stderr:{data.Data}");
                };

                proc.StartInfo.FileName = fileName;
                proc.StartInfo.Arguments = arguments;
                var cmdString = $"{proc.StartInfo.FileName} {proc.StartInfo.Arguments}";
                //Console.WriteLine($"Running: {proc.StartInfo.FileName} {proc.StartInfo.Arguments}");

                var started = proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
                proc.WaitForExit();

                return cmdString;
            }
        }

        // key which was encrypted with SSH public key
        // is then decrypted with SSH private key
        // returns the symmetricKey written to file
        static (String, String) DecryptSymmetricKeyWithOpenSSL(String privateKeyFile, String encryptedKeyFile)
        {
            var symmetricKeyFile = Path.GetTempFileName();
            var cmdString = RunSimpleProcess("openssl", $"rsautl -decrypt -oaep -inkey {privateKeyFile} -in {encryptedKeyFile} -out {symmetricKeyFile}", "rsautl");
            return (symmetricKeyFile, cmdString);
        }

        // decrypts text with symmetricKey using AES
        // returns the plainText written to file
        static (String, String) DecryptTextWithOpenSSL(String encryptedTextFile, String symmetricKeyFile)
        {
            var plainTextFile = Path.GetTempFileName();
            var cmdString = RunSimpleProcess("openssl", $"enc -aes-256-cbc -d -base64 -A -md sha256 -in {encryptedTextFile} -out {plainTextFile} -pass file:{symmetricKeyFile}", "decrypt");
            return (plainTextFile, cmdString);
        }
    }
}
