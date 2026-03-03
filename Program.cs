using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Lösenordshanterare
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // =====================================================
            // *** NYTT ***
            // Router: välj kommando från args[0]
            // =====================================================
            if (args.Length == 0)
            {
                Console.WriteLine("Fel: Inget kommando angivet.");
                Console.WriteLine("Exempel: init client.json server.json");
                Console.WriteLine("Exempel: secret client.json");
                return;
            }

            string command = args[0].ToLowerInvariant();

            switch (command)
            {
                case "init":
                    RunInit(args);
                    break;

                case "secret":
                    RunSecret(args);
                    break;

                case "get":
                    RunGet(args);
                    break;

                case "set":
                    RunSet(args);
                    break;

                default:
                    Console.WriteLine($"Fel: Okänt kommando '{args[0]}'.");
                    break;
            }
        }

        // =====================================================
        // *** NYTT ***
        // INIT: init <client> <server> {<pwd>}
        // Skapar nya filer (override), krypterar tomt vault, printar secret.
        // =====================================================
        static void RunInit(string[] args)
        {
            // Manual: init <client> <server>
            if (args.Length != 3)
            {
                Console.WriteLine("Fel: Syntax: init <client> <server>");
                return;
            }

            string clientPath = args[1];
            string serverPath = args[2];

            Console.Write("Ange master password: ");
            string masterPassword = Console.ReadLine();

            // 1) Skapa secret key (32 bytes)
            byte[] secretKeyBytes = new byte[32];
            RandomNumberGenerator.Fill(secretKeyBytes);
            string secretB64 = Convert.ToBase64String(secretKeyBytes);

            // 2) Skapa IV (16 bytes)
            byte[] ivBytes = new byte[16];
            RandomNumberGenerator.Fill(ivBytes);
            string ivB64 = Convert.ToBase64String(ivBytes);

            // 3) Derivera vaultKey med PBKDF2 (Alternativ B: IV används som salt)
            byte[] vaultKey = DeriveVaultKey_UsingIvAsSalt(secretKeyBytes, masterPassword, ivBytes);

            // 4) Skapa tomt valv och kryptera
            var vaultInit = new Dictionary<string, string>();
            vaultInit["test.example.com"] = "hemligt123";
            string vaultJson = JsonSerializer.Serialize(vaultInit);
            byte[] plaintext = Encoding.UTF8.GetBytes(vaultJson);

            byte[] ciphertext = EncryptVault(plaintext, vaultKey, ivBytes);

            // 5) Skriv client.json (override utan prompt)
            var clientDict = new Dictionary<string, string>
            {
                { "secret", secretB64 }
            };
            File.WriteAllText(clientPath, JsonSerializer.Serialize(clientDict));

            // 6) Skriv server.json (override utan prompt)
            var serverDict = new Dictionary<string, string>
            {
                { "iv", ivB64 },
                { "vault", Convert.ToBase64String(ciphertext) }
            };
            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverDict));

            // Manual: "Your secret key will be printed in plain-text to standard out"
            Console.WriteLine(secretB64);
        }

        // =====================================================
        // *** NYTT (lätt kommando, bra för att testa args-routing) ***
        // SECRET: secret <client>
        // Skriver ut secret key som finns i client.json
        // =====================================================
        static void RunSecret(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Fel: Syntax: secret <client>");
                return;
            }

            string clientPath = args[1];

            if (!File.Exists(clientPath))
            {
                Console.WriteLine("Fel: Client-filen finns inte.");
                return;
            }

            Dictionary<string, string>? clientData;
            try
            {
                clientData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientPath));
            }
            catch
            {
                Console.WriteLine("Fel: Client-filen är inte giltig JSON.");
                return;
            }

            if (clientData == null || !clientData.TryGetValue("secret", out string secretB64) || string.IsNullOrWhiteSpace(secretB64))
            {
                Console.WriteLine("Fel: Client-filen saknar 'secret'.");
                return;
            }

            Console.WriteLine(secretB64);
        }
        static void RunGet(string[] args)
        {
            // get <client> <server> [<prop>]
            if (args.Length != 3 && args.Length != 4)
            {
                Console.WriteLine("Fel: Syntax: get <client> <server> [<prop>]");
                return;
            }

            string clientPath = args[1];
            string serverPath = args[2];
            string? prop = (args.Length == 4) ? args[3] : null;

            // -----------------------------------------------------
            // 1) Läs client.json och hämta "secret"
            // -----------------------------------------------------
            if (!File.Exists(clientPath))
            {
                Console.WriteLine("Fel: Client-filen finns inte.");
                return;
            }

            Dictionary<string, string>? clientData;
            try
            {
                clientData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientPath));
            }
            catch
            {
                Console.WriteLine("Fel: Client-filen är inte giltig JSON.");
                return;
            }

            if (clientData == null || !clientData.ContainsKey("secret"))
            {
                Console.WriteLine("Fel: Client-filen saknar 'secret'.");
                return;
            }

            string secretB64 = clientData["secret"];
            byte[] secretKeyBytes;
            try
            {
                secretKeyBytes = Convert.FromBase64String(secretB64);
            }
            catch
            {
                Console.WriteLine("Fel: Client-filens 'secret' är inte giltig Base64.");
                return;
            }

            // -----------------------------------------------------
            // 2) Läs server.json och hämta "iv" och "vault"
            // -----------------------------------------------------
            if (!File.Exists(serverPath))
            {
                Console.WriteLine("Fel: Server-filen finns inte.");
                return;
            }

            Dictionary<string, string>? serverData;
            try
            {
                serverData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));
            }
            catch
            {
                Console.WriteLine("Fel: Server-filen är inte giltig JSON.");
                return;
            }

            if (serverData == null || !serverData.ContainsKey("iv") || !serverData.ContainsKey("vault"))
            {
                Console.WriteLine("Fel: Server-filen saknar 'iv' och/eller 'vault'.");
                return;
            }

            byte[] ivBytes;
            byte[] ciphertext;
            try
            {
                ivBytes = Convert.FromBase64String(serverData["iv"]);
                ciphertext = Convert.FromBase64String(serverData["vault"]);
            }
            catch
            {
                Console.WriteLine("Fel: Server-filens 'iv' eller 'vault' är inte giltig Base64.");
                return;
            }

            // -----------------------------------------------------
            // 3) Fråga master password (interaktivt enligt {<pwd>})
            // -----------------------------------------------------
            Console.Write("Ange master password: ");
            string masterPassword = Console.ReadLine();

            // -----------------------------------------------------
            // 4) Skapa vaultKey och dekryptera vaultet
            // -----------------------------------------------------
            byte[] vaultKey = DeriveVaultKey_UsingIvAsSalt(secretKeyBytes, masterPassword, ivBytes);

            Dictionary<string, string> vault;
            try
            {
                byte[] decrypted = DecryptVault(ciphertext, vaultKey, ivBytes);
                string jsonBack = Encoding.UTF8.GetString(decrypted);

                vault = JsonSerializer.Deserialize<Dictionary<string, string>>(jsonBack)
                        ?? new Dictionary<string, string>();
            }
            catch
            {
                Console.WriteLine("Fel: Fel master password eller fel client/server (kunde inte dekryptera).");
                return;
            }

            // -----------------------------------------------------
            // 5) Output enligt manualen
            // -----------------------------------------------------
            if (string.IsNullOrEmpty(prop))
            {
                // Listar alla props (men inte deras värden)
                foreach (var key in vault.Keys)
                {
                    Console.WriteLine(key);
                }
                return;
            }

            // Om prop finns: skriv värdet om det finns, annars skriv inget
            if (vault.TryGetValue(prop, out string value))
            {
                Console.WriteLine(value);
            }
        }
        static void RunSet(string[] args)
        {
            // set <client> <server> <prop> [-g|--generate]
            if (args.Length < 4 || args.Length > 5)
            {
                Console.WriteLine("Fel: Syntax: set <client> <server> <prop> [-g|--generate]");
                return;
            }

            string clientPath = args[1];
            string serverPath = args[2];
            string prop = args[3];

            bool generate = false;
            if (args.Length == 5)
            {
                string flag = args[4];
                generate = flag == "-g" || flag == "--generate";
                if (!generate)
                {
                    Console.WriteLine("Fel: Okänd flagga. Använd -g eller --generate.");
                    return;
                }
            }

            // 1) Läs client.json -> secret
            if (!File.Exists(clientPath))
            {
                Console.WriteLine("Fel: Client-filen finns inte.");
                return;
            }

            Dictionary<string, string>? clientData;
            try
            {
                clientData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientPath));
            }
            catch
            {
                Console.WriteLine("Fel: Client-filen är inte giltig JSON.");
                return;
            }

            if (clientData == null || !clientData.ContainsKey("secret"))
            {
                Console.WriteLine("Fel: Client-filen saknar 'secret'.");
                return;
            }

            byte[] secretKeyBytes;
            try
            {
                secretKeyBytes = Convert.FromBase64String(clientData["secret"]);
            }
            catch
            {
                Console.WriteLine("Fel: Client-filens 'secret' är inte giltig Base64.");
                return;
            }

            // 2) Läs server.json -> iv + vault
            if (!File.Exists(serverPath))
            {
                Console.WriteLine("Fel: Server-filen finns inte.");
                return;
            }

            Dictionary<string, string>? serverData;
            try
            {
                serverData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));
            }
            catch
            {
                Console.WriteLine("Fel: Server-filen är inte giltig JSON.");
                return;
            }

            if (serverData == null || !serverData.ContainsKey("iv") || !serverData.ContainsKey("vault"))
            {
                Console.WriteLine("Fel: Server-filen saknar 'iv' och/eller 'vault'.");
                return;
            }

            byte[] ivBytes;
            byte[] ciphertext;
            try
            {
                ivBytes = Convert.FromBase64String(serverData["iv"]);
                ciphertext = Convert.FromBase64String(serverData["vault"]);
            }
            catch
            {
                Console.WriteLine("Fel: Server-filens 'iv' eller 'vault' är inte giltig Base64.");
                return;
            }

            // 3) Fråga master password
            Console.Write("Ange master password: ");
            string masterPassword = Console.ReadLine();

            // 4) Dekryptera vault
            byte[] vaultKey = DeriveVaultKey_UsingIvAsSalt(secretKeyBytes, masterPassword, ivBytes);

            Dictionary<string, string> vault;
            try
            {
                byte[] decrypted = DecryptVault(ciphertext, vaultKey, ivBytes);
                string jsonBack = Encoding.UTF8.GetString(decrypted);

                vault = JsonSerializer.Deserialize<Dictionary<string, string>>(jsonBack)
                        ?? new Dictionary<string, string>();
            }
            catch
            {
                Console.WriteLine("Fel: Fel master password eller fel client/server (kunde inte dekryptera).");
                return;
            }

            // 5) Läs value (eller generera)
            string value;
            if (generate)
            {
                value = GeneratePassword20();
                // Manualen: genererat lösenord ska skrivas ut
                Console.WriteLine(value);
            }
            else
            {
                Console.Write("Ange value att spara: ");
                value = Console.ReadLine();
            }

            // 6) Uppdatera vault
            vault[prop] = value;

            // 7) Kryptera om och spara tillbaka
            string vaultJson = JsonSerializer.Serialize(vault);
            byte[] plaintext = Encoding.UTF8.GetBytes(vaultJson);
            byte[] newCipher = EncryptVault(plaintext, vaultKey, ivBytes);

            serverData["vault"] = Convert.ToBase64String(newCipher);

            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverData));
        }
        static string GeneratePassword20()
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var sb = new StringBuilder(20);

            byte[] bytes = new byte[20];
            RandomNumberGenerator.Fill(bytes);

            for (int i = 0; i < 20; i++)
                sb.Append(chars[bytes[i] % chars.Length]);

            return sb.ToString();
        }

        // =====================================================
        // (BEHÅLLER er kryptokod, samma som ni redan har)
        // =====================================================
        static byte[] DeriveVaultKey_UsingIvAsSalt(byte[] secretKeyBytes, string masterPassword, byte[] ivBytes)
        {
            string combined = masterPassword + ":" + Convert.ToBase64String(secretKeyBytes);

            using var pbkdf2 = new Rfc2898DeriveBytes(
                password: combined,
                salt: ivBytes,
                iterations: 100_000,
                hashAlgorithm: HashAlgorithmName.SHA256);

            return pbkdf2.GetBytes(32); // AES-256
        }

        static byte[] EncryptVault(byte[] plaintext, byte[] vaultKey, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Key = vaultKey;
            aes.IV = iv;

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        static byte[] DecryptVault(byte[] ciphertext, byte[] vaultKey, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Key = vaultKey;
            aes.IV = iv;

            using ICryptoTransform decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }
    }
}