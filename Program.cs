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

            // 1) Skapa client om den inte finns (secret key)
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

            // 2) Skapa server om den inte finns (bara IV enligt spec)
            if (!File.Exists(serverPath) || new FileInfo(serverPath).Length == 0)
            {
                byte[] ivBytesInit = new byte[16];
                RandomNumberGenerator.Fill(ivBytesInit);
                string ivB64Init = Convert.ToBase64String(ivBytesInit);

                File.WriteAllText(serverPath, ivB64Init);
                Console.WriteLine("iv är skapad och fil är skapad");
            }

            // Läs IV (bytes)
            string ivB64 = File.ReadAllText(serverPath).Trim();
            byte[] ivBytes = Convert.FromBase64String(ivB64);

            // 3) Master password från användaren
            Console.Write("Ange master password: ");
            string masterPassword = Console.ReadLine();

            // 4) Alternativ B: Använd IV som PBKDF2-salt (ingen extra lagring)
            byte[] vaultKey = DeriveVaultKey_UsingIvAsSalt(secretKeyBytes, masterPassword, ivBytes);

            // Test-utskrift (TA BORT SENARE)
            Console.WriteLine("VaultKey length: " + vaultKey.Length);
            Console.WriteLine("VaultKey (Base64): " + Convert.ToBase64String(vaultKey));

            // 5) Skapar ett vault (fortfarande okrypterat här – AES kommer sen)
            Dictionary<string, string> vault = new Dictionary<string, string>();
            vault.Add("netflix.com", "hemligt123");
            vault.Add("google.com", "lösenord456");

            string json = JsonSerializer.Serialize(vault);
            Console.WriteLine(json);

            var restoredVault = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            foreach (var item in restoredVault)
            {
                Console.WriteLine($"Konto: {item.Key}, Lösenord: {item.Value}");
            }
        }

        static byte[] DeriveVaultKey_UsingIvAsSalt(byte[] secretKeyBytes, string masterPassword, byte[] ivBytes)
        {
            // Kombinera master password + secretKey till input för PBKDF2
            string combined = masterPassword + ":" + Convert.ToBase64String(secretKeyBytes);

            using var pbkdf2 = new Rfc2898DeriveBytes(
                password: combined,
                salt: ivBytes,                  // <-- IV används som salt
                iterations: 100_000,
                hashAlgorithm: HashAlgorithmName.SHA256);

            // 32 bytes = AES-256 nyckel
            return pbkdf2.GetBytes(32);
        }
    }
}