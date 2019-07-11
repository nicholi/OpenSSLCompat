using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace OpenSSLCompat
{
    class OtherTests
    {
        static (String, String) EncryptTextWithOpenSSL(String plainTextFile, String symmetricKeyFile)
        {
            var encryptedTextFile = Path.GetTempFileName();
            var cmdString = Program.RunSimpleProcess("openssl", $"enc -aes-256-cbc -e -base64 -A -md sha256 -salt -in {plainTextFile} -out {encryptedTextFile} -pass file:{symmetricKeyFile}", "encrypt");
            return (encryptedTextFile, cmdString);
        }

        static (String, String) EncryptSymmetricWithOpenSSL(String symmetricKeyFile, String publicKeyFile)
        {
            var encryptedKeyFile = Path.GetTempFileName();

            // have to convert public key to PKCS8 format for openssl to encrypt with rsautl
            var publicKeyPKCS8 = new StringBuilder();
            using (var proc = new Process())
            {
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.CreateNoWindow = true;

                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;

                proc.OutputDataReceived += (sender, data) => {
                    //Console.WriteLine($"ssh-keygen:{data.Data}");
                    publicKeyPKCS8.Append(data.Data + "\n");
                };
                proc.ErrorDataReceived += (sender, data) => {
                    //Console.WriteLine($"ssh-keygen:{data.Data}");
                };

                proc.StartInfo.FileName = "ssh-keygen";
                proc.StartInfo.Arguments = $"-e -f {publicKeyFile} -m PKCS8";
                //Console.WriteLine($"Running: {proc.StartInfo.FileName} {proc.StartInfo.Arguments}");

                var started = proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
                proc.WaitForExit();
            }

            var publicKeyPKCS8File = Path.GetTempFileName();
            File.WriteAllText(publicKeyPKCS8File, publicKeyPKCS8.ToString());

            var rsaUtlCmdString = Program.RunSimpleProcess("openssl", $"rsautl -encrypt -oaep -pubin -inkey {publicKeyPKCS8File} -in {symmetricKeyFile} -out {encryptedKeyFile}", "rsautl");
            return (encryptedKeyFile, rsaUtlCmdString);
        }
    }
}
