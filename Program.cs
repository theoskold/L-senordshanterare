using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace Lösenordshanterare
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string clientPath = "client.txt";
            string serverPath = "server.txt";

            // =====================================================
            // 1) SKAPA CLIENT (SECRET KEY)
            // =====================================================
            if (!File.Exists(clientPath) || new FileInfo(clientPath).Length == 0)
            {
                byte[] keyBytes = new byte[32];
                RandomNumberGenerator.Fill(keyBytes);

                string secretKey = Convert.ToBase64String(keyBytes);
                File.WriteAllText(clientPath, secretKey);

                Console.WriteLine("secret key är skapad och fil är skapad");
            }

            // Läs secret key (bytes)
            string secretKeyB64 = File.ReadAllText(clientPath).Trim();
            byte[] secretKeyBytes = Convert.FromBase64String(secretKeyB64);

            // =====================================================
            // 2) SKAPA SERVER (IV + KRYPTATERAT VALV)
            // =====================================================

            if (!File.Exists(serverPath) || new FileInfo(serverPath).Length == 0)
            {
                // Skapa IV
                byte[] ivBytesInit = new byte[16];
                RandomNumberGenerator.Fill(ivBytesInit);
                string ivB64Init = Convert.ToBase64String(ivBytesInit);

                // *** NYTT ***
                // Fråga efter master password vid första skapandet
                Console.Write("Ange master password: ");
                string masterPasswordInit = Console.ReadLine();

                // *** NYTT ***
                // Skapa vaultKey med PBKDF2 (IV används som salt)
                byte[] vaultKeyInit =
                    DeriveVaultKey_UsingIvAsSalt(secretKeyBytes, masterPasswordInit, ivBytesInit);

                // *** NYTT ***
                // Skapa ett tomt valv första gången
                Dictionary<string, string> vaultInit = new Dictionary<string, string>();
                string jsonInit = JsonSerializer.Serialize(vaultInit);

                byte[] plaintextInit =
                    System.Text.Encoding.UTF8.GetBytes(jsonInit);

                // *** NYTT ***
                // Kryptera valvet med AES
                byte[] ciphertextInit =
                    EncryptVault(plaintextInit, vaultKeyInit, ivBytesInit);

                // *** ÄNDRAT ***
                // Tidigare sparades bara IV
                // Nu sparar vi IV + krypterat valv (2 rader)
                File.WriteAllLines(serverPath, new[]
                {
                    ivB64Init,
                    Convert.ToBase64String(ciphertextInit)
                });

                Console.WriteLine("iv + krypterat valv är skapade och fil är skapad");
            }

            // =====================================================
            // 3) LÄS IV + CIPHERTEXT FRÅN SERVER
            // =====================================================

            // *** ÄNDRAT ***
            // Tidigare läste vi bara IV
            // Nu läser vi två rader: IV + ciphertext
            string[] serverLines = File.ReadAllLines(serverPath);

            string ivB64 = serverLines[0].Trim();
            string cipherB64 = serverLines[1].Trim();

            byte[] ivBytes = Convert.FromBase64String(ivB64);
            byte[] ciphertextFromFile = Convert.FromBase64String(cipherB64);

            // =====================================================
            // 4) MASTER PASSWORD VID ÖPPNING
            // =====================================================

            Console.Write("Ange master password: ");
            string masterPassword = Console.ReadLine();

            // *** SAMMA SOM TIDIGARE ***
            byte[] vaultKey =
                DeriveVaultKey_UsingIvAsSalt(secretKeyBytes, masterPassword, ivBytes);

            // =====================================================
            // 5) DEKRYPTERA VALVET
            // =====================================================

            try
            {
                // *** NYTT ***
                // Dekryptera det sparade valvet
                byte[] decrypted =
                    DecryptVault(ciphertextFromFile, vaultKey, ivBytes);

                string jsonBack =
                    System.Text.Encoding.UTF8.GetString(decrypted);

                var restoredVault =
                    JsonSerializer.Deserialize<Dictionary<string, string>>(jsonBack)
                    ?? new Dictionary<string, string>();

                Console.WriteLine("Valvets innehåll:");
                foreach (var item in restoredVault)
                {
                    Console.WriteLine($"Konto: {item.Key}, Lösenord: {item.Value}");
                }
            }
            catch
            {
                Console.WriteLine("Fel master password (kunde inte dekryptera valvet).");
            }
        }

        // =====================================================
        // PBKDF2 (IV används som salt - Alternativ B)
        // =====================================================
        static byte[] DeriveVaultKey_UsingIvAsSalt(
            byte[] secretKeyBytes,
            string masterPassword,
            byte[] ivBytes)
        {
            string combined =
                masterPassword + ":" + Convert.ToBase64String(secretKeyBytes);

            using var pbkdf2 = new Rfc2898DeriveBytes(
                password: combined,
                salt: ivBytes,          // *** IV används som salt ***
                iterations: 100_000,
                hashAlgorithm: HashAlgorithmName.SHA256);

            return pbkdf2.GetBytes(32); // AES-256
        }

        // =====================================================
        // AES KRYPTATERING
        // =====================================================
        static byte[] EncryptVault(byte[] plaintext, byte[] vaultKey, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Key = vaultKey;
            aes.IV = iv;

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(
                plaintext, 0, plaintext.Length);
        }

        // =====================================================
        // AES DEKRYPTATERING
        // =====================================================
        static byte[] DecryptVault(byte[] ciphertext, byte[] vaultKey, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Key = vaultKey;
            aes.IV = iv;

            using ICryptoTransform decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(
                ciphertext, 0, ciphertext.Length);
        }
    }
}