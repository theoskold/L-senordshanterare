using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Lösenordshanterare
{
    //Allmän innehållsförteckning
    // Init rad 75
    // Secret rad 131
    // Get rad 168
    // Set rad 294
    // Create rad 448
    // Delete rad 546
    // Change rad 664
    // autoGeneratePassword rad 785
    // DeriveVaultKey rad 802
    // EncryptVault rad 816
    // DecryptVault rad 827
    public class Program
    {
        public static void Main(string[] args)
        {

            if (args.Length == 0)
            {
                Console.WriteLine("Inget kommando angivet, ange giltigt kommando");


                return;
            }

            string command = args[0].ToLower();

            switch (command)
            {
                case "init":
                    Init(args);
                    break;

                case "secret":
                    Secret(args);
                    break;

                case "create":
                    Create(args);
                    break;

                case "get":
                    Get(args);
                    break;

                case "set":
                    Set(args);
                    break;

                case "delete":
                    Delete(args);
                    break;

                case "change":
                    Change(args);
                    break;

                default:
                    Console.WriteLine("Ange ett giltigt kommando");
                    break;
            }
        }


        //Skapar valv, client och serverfil
        static void Init(string[] args)
        {

            if (args.Length != 3)
            {
                Console.WriteLine("Felaktig syntax angivet, för init, använd: init <client> <server>");

                return;
            }

            string clientPath = args[1];
            string serverPath = args[2];

            Console.Write("Ange ditt master-password: ");
            string masterPassword = Console.ReadLine() ?? "";

            byte[] secretKey = new byte[32];
            RandomNumberGenerator.Fill(secretKey);
            string secretKeyBase64 = Convert.ToBase64String(secretKey);


            byte[] iv = new byte[16];
            RandomNumberGenerator.Fill(iv);
            string ivBase64 = Convert.ToBase64String(iv);


            byte[] vaultKey = DeriveVaultKey(secretKey, masterPassword);

            var vaultNew = new Dictionary<string, string>();

            string vaultToJson = JsonSerializer.Serialize(vaultNew);
            byte[] vaultBytes = Encoding.UTF8.GetBytes(vaultToJson);

            byte[] encryptedBytes = EncryptVault(vaultBytes, vaultKey, iv);


            var clientDictionary = new Dictionary<string, string>
            {
                { "secret", secretKeyBase64 }
            };
            File.WriteAllText(clientPath, JsonSerializer.Serialize(clientDictionary));


            var serverDictionary = new Dictionary<string, string>
            {
                { "iv", ivBase64 },
                { "vault", Convert.ToBase64String(encryptedBytes) }
            };
            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverDictionary));


            Console.WriteLine(secretKeyBase64);
        }


        // Skriver ut secret key från clientfil. 
        static void Secret(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Felaktig syntax angivet, för secret, använd: secret <client>");
                return;
            }

            string clientPath = args[1];

            if (!File.Exists(clientPath))
            {
                Console.WriteLine("Det finns ingen Client-fil. ");
                return;
            }

            Dictionary<string, string>? clientData;
            try
            {
                clientData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientPath));
            }
            catch
            {
                Console.WriteLine("Client-filen är inte en giltig JSON.");
                return;
            }

            if (clientData == null || !clientData.TryGetValue("secret", out string secretKeyBase64) || string.IsNullOrWhiteSpace(secretKeyBase64))
            {
                Console.WriteLine("Client-filen saknar  en giltig secret-key.");
                return;
            }

            Console.WriteLine(secretKeyBase64);
        }

        //Skapar vaultkey, hämtar och decrypterar innehållet med hjälp av secret key, iv och master password
        static void Get(string[] args)
        {

            if (args.Length != 3 && args.Length != 4)
            {
                Console.WriteLine("Felaktig syntax angivet, för get, använd: get <client> <server> [<prop>]");
                return;
            }

            string clientPath = args[1];
            string serverPath = args[2];
            string? prop = (args.Length == 4) ? args[3] : null;


            if (!File.Exists(clientPath))
            {
                Console.WriteLine("Client-filen existerar inte.");
                return;
            }

            Dictionary<string, string>? clientData;
            try
            {
                clientData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientPath));
            }
            catch
            {
                Console.WriteLine("Client-filen är inte en giltig JSON.");
                return;
            }

            if (clientData == null || !clientData.ContainsKey("secret"))
            {
                Console.WriteLine("Client-filen saknar en giltig secret-key.");
                return;
            }

            string secretKeyBase64 = clientData["secret"];
            byte[] secretKey;
            try
            {
                secretKey = Convert.FromBase64String(secretKeyBase64);
            }
            catch
            {
                Console.WriteLine("Secret för client-filen är inte i giltigt Base64-format.");
                return;
            }


            if (!File.Exists(serverPath))
            {
                Console.WriteLine("Server-filen existerar inte.");
                return;
            }

            Dictionary<string, string>? serverData;
            try
            {
                serverData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));
            }
            catch
            {
                Console.WriteLine("Server-filen är inte en giltig JSON");
                return;
            }

            if (serverData == null || !serverData.ContainsKey("iv") || !serverData.ContainsKey("vault"))
            {
                Console.WriteLine("Server-filen saknar iv och/eller vault, eller är null.");
                return;
            }

            byte[] iv;
            byte[] encryptedBytes;
            try
            {
                iv = Convert.FromBase64String(serverData["iv"]);
                encryptedBytes = Convert.FromBase64String(serverData["vault"]);
            }
            catch
            {
                Console.WriteLine("Server-filens iv eller vault är inte i giltigt Base64-format.");
                return;
            }


            Console.WriteLine("Ange ditt master password: ");
            string masterPassword = Console.ReadLine() ?? "";


            byte[] vaultKey = DeriveVaultKey(secretKey, masterPassword);

            Dictionary<string, string> vault;
            try
            {
                byte[] decryptedBytes = DecryptVault(encryptedBytes, vaultKey, iv);
                string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);

                vault = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedJson)
                        ?? new Dictionary<string, string>();
            }
            catch
            {
                Console.WriteLine("Dekrypteringen misslyckades, angett rätt lösenord?");
                return;
            }


            if (string.IsNullOrEmpty(prop))
            {

                foreach (var key in vault.Keys)
                {
                    Console.WriteLine(key);
                }
                return;
            }


            if (vault.TryGetValue(prop, out string value))
            {
                Console.WriteLine(value);
            }
        }
        //Decrypterar, skapar eller uppdaterar värden och krypterar sedan igen
        static void Set(string[] args)
        {

            if (args.Length < 4 || args.Length > 5)
            {
                Console.WriteLine("Felaktig syntax angivet, för set, använd: set <client> <server> <prop> [-g]");
                return;
            }

            string clientPath = args[1];
            string serverPath = args[2];
            string prop = args[3];

            bool generate = false;

            if (args.Length == 5)
            {
                if (args[4] == "-g")
                {
                    generate = true;
                }
                else
                {
                    if (args[4] == "--generate")
                    {
                        generate = true;
                    }
                    else
                    {
                        Console.WriteLine("Okänt input. Använd -g eller --generate.");
                        return;
                    }
                }
            }


            if (!File.Exists(clientPath))
            {
                Console.WriteLine("Client-filen existerar inte.");
                return;
            }

            Dictionary<string, string>? clientData;
            try
            {
                clientData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientPath));
            }
            catch
            {
                Console.WriteLine("Client-filen är inte i giltigt JSON-format.");
                return;
            }

            if (clientData == null || !clientData.ContainsKey("secret"))
            {
                Console.WriteLine("Client-filen saknar en giltig secret-key.");
                return;
            }

            byte[] secretKey;
            try
            {
                secretKey = Convert.FromBase64String(clientData["secret"]);
            }
            catch
            {
                Console.WriteLine("Secret för client-filen är inte i giltigt Base64-format.");
                return;
            }


            if (!File.Exists(serverPath))
            {
                Console.WriteLine("Server-filen existerar inte.");
                return;
            }

            Dictionary<string, string>? serverData;
            try
            {
                serverData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));
            }
            catch
            {
                Console.WriteLine("Server-filen är inte i giltigt JSON-format.");
                return;
            }

            if (serverData == null || !serverData.ContainsKey("iv") || !serverData.ContainsKey("vault"))
            {
                Console.WriteLine("Server-filen saknar iv och/eller vault, eller är null.");
                return;
            }

            byte[] iv;
            byte[] encryptedBytes;
            try
            {
                iv = Convert.FromBase64String(serverData["iv"]);
                encryptedBytes = Convert.FromBase64String(serverData["vault"]);
            }
            catch
            {
                Console.WriteLine("Server-filens iv eller vault är inte i giltigt Base64-format.");
                return;
            }


            Console.Write("Ange master password: ");
            string masterPassword = Console.ReadLine() ?? "";


            byte[] vaultKey = DeriveVaultKey(secretKey, masterPassword);

            Dictionary<string, string> vault;
            try
            {
                byte[] decryptedBytes = DecryptVault(encryptedBytes, vaultKey, iv);
                string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);

                vault = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedJson)
                        ?? new Dictionary<string, string>();
            }
            catch
            {
                Console.WriteLine("Dekrypteringen misslyckades, angett rätt lösenord?");
                return;
            }


            string value;
            if (generate)
            {
                value = autoGeneratePassword();
                Console.WriteLine(value);
            }
            else
            {
                Console.WriteLine("Ange ett lösenord att spara: ");
                value = Console.ReadLine() ?? "";
            }

            vault[prop] = value;

            string vaultToJson = JsonSerializer.Serialize(vault);
            byte[] vaultBytes = Encoding.UTF8.GetBytes(vaultToJson);
            byte[] encryptedBytesNew = EncryptVault(vaultBytes, vaultKey, iv);

            serverData["vault"] = Convert.ToBase64String(encryptedBytesNew);

            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverData));
        }

        // Skapar en ny client fil med hjälp av master password och den redan existerande secret keyn.    
        static void Create(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("Felaktig syntax angivet, för create, använd: create <client> <server>");
                return;
            }

            string clientPath = args[1];
            string serverPath = args[2];

            if (!File.Exists(serverPath))
            {
                Console.WriteLine("Server-filen existerar inte.");
                return;
            }

            Dictionary<string, string>? serverData;
            try
            {
                serverData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));
            }
            catch
            {
                Console.WriteLine("Server-filen är inte i giltigt JSON-format.");
                return;
            }

            if (serverData == null || !serverData.ContainsKey("iv") || !serverData.ContainsKey("vault"))
            {
                Console.WriteLine("Server-filen saknar iv och/eller vault, eller är null.");
                return;
            }

            byte[] iv;
            byte[] encryptedBytes;
            try
            {
                iv = Convert.FromBase64String(serverData["iv"]);
                encryptedBytes = Convert.FromBase64String(serverData["vault"]);
            }
            catch
            {
                Console.WriteLine("Server-filens iv eller vault är inte i giltigt Base64-format.");
                return;
            }

            Console.WriteLine("Ange master password: ");
            string masterPassword = Console.ReadLine() ?? "";

            Console.WriteLine("Ange secret key: ");
            string secretKeyBase64 = Console.ReadLine() ?? "";

            if (string.IsNullOrWhiteSpace(secretKeyBase64))
            {
                Console.WriteLine("Du har inte angett en secret key.");
                return;
            }

            byte[] secretKey;
            try
            {
                secretKey = Convert.FromBase64String(secretKeyBase64);
            }
            catch
            {
                Console.WriteLine("Secret key är inte i giltigt JSON-format.");
                return;
            }

            byte[] vaultKey = DeriveVaultKey(secretKey, masterPassword);

            Dictionary<string, string> vault;
            try
            {
                byte[] decryptedBytes = DecryptVault(encryptedBytes, vaultKey, iv);
                string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);

                vault = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedJson)
                    ?? new Dictionary<string, string>();
            }
            catch
            {
                Console.WriteLine("Dekrypteringen misslyckades, angett rätt lösenord?");
                return;
            }


            var clientDictionary = new Dictionary<string, string>
            {
                { "secret", secretKeyBase64 }
            };


            File.WriteAllText(clientPath, JsonSerializer.Serialize(clientDictionary));
        }

        //Används för att ta bort värden
        static void Delete(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("Felaktig syntax angivet, för set, använd: delete <client> <server> <prop>");
                return;
            }

            string clientPath = args[1];
            string serverPath = args[2];
            string prop = args[3];

            if (!File.Exists(clientPath))
            {
                Console.WriteLine("Client-filen existerar inte.");
                return;
            }

            Dictionary<string, string>? clientData;
            try
            {
                clientData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientPath));
            }
            catch
            {
                Console.WriteLine("Client-filen är inte i giltigt JSON-format.");
                return;
            }

            if (clientData == null || !clientData.ContainsKey("secret"))
            {
                Console.WriteLine("Client-filen saknar en giltig secret-key.");
                return;
            }

            byte[] secretKey;
            try
            {
                secretKey = Convert.FromBase64String(clientData["secret"]);
            }
            catch
            {
                Console.WriteLine("Secret key för client-filen är inte i giltigt Base64-format.");
                return;
            }


            if (!File.Exists(serverPath))
            {
                Console.WriteLine("Server-filen existerar inte.");
                return;
            }

            Dictionary<string, string>? serverData;
            try
            {
                serverData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));
            }
            catch
            {
                Console.WriteLine("Server-filen är inte i giltigt JSON-format.");
                return;
            }

            if (serverData == null || !serverData.ContainsKey("iv") || !serverData.ContainsKey("vault"))
            {
                Console.WriteLine("Server-filen saknar iv och/eller vault, eller är null.");
                return;
            }

            byte[] iv;
            byte[] encryptedBytes;
            try
            {
                iv = Convert.FromBase64String(serverData["iv"]);
                encryptedBytes = Convert.FromBase64String(serverData["vault"]);
            }
            catch
            {
                Console.WriteLine("Server-filens iv eller vault är inte i giltigt Base64-format.");
                return;
            }


            Console.WriteLine("Ange master password: ");
            string masterPassword = Console.ReadLine() ?? "";

            byte[] vaultKey = DeriveVaultKey(secretKey, masterPassword);

            Dictionary<string, string> vault;
            try
            {
                byte[] decryptedBytes = DecryptVault(encryptedBytes, vaultKey, iv);
                string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);

                vault = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedJson)
                        ?? new Dictionary<string, string>();
            }
            catch
            {
                Console.WriteLine("Dekrypteringen misslyckades, angett rätt lösenord?");
                return;
            }


            vault.Remove(prop);

            string vaultToJson = JsonSerializer.Serialize(vault);
            byte[] vaultBytes = Encoding.UTF8.GetBytes(vaultToJson);
            byte[] encryptedBytesNew = EncryptVault(vaultBytes, vaultKey, iv);

            serverData["vault"] = Convert.ToBase64String(encryptedBytesNew);

            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverData));
        }


        //Används för att skapa nytt master password 
        static void Change(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("Felaktig syntax angivet, för set, använd: change <client> <server>");
                return;
            }

            string clientPath = args[1];
            string serverPath = args[2];

            if (!File.Exists(clientPath))
            {
                Console.WriteLine("Client-filen existerar inte.");
                return;
            }

            Dictionary<string, string>? clientData;
            try
            {
                clientData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientPath));
            }
            catch
            {
                Console.WriteLine("Client-filen är inte i giltigt JSON-format.");
                return;
            }

            if (clientData == null || !clientData.TryGetValue("secret", out string secretKeyBase64) || string.IsNullOrWhiteSpace(secretKeyBase64))
            {
                Console.WriteLine("Client-filen saknar en giltig secret-key.");
                return;
            }

            byte[] secretKey;
            try
            {
                secretKey = Convert.FromBase64String(secretKeyBase64);
            }
            catch
            {
                Console.WriteLine("Secret key för client-filen är inte i giltigt Base64-format.");
                return;
            }

            if (!File.Exists(serverPath))
            {
                Console.WriteLine("Server-filen existerar inte.");
                return;
            }

            Dictionary<string, string>? serverData;
            try
            {
                serverData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));
            }
            catch
            {
                Console.WriteLine("Server-filen är inte i giltigt JSON-format.");
                return;
            }

            if (serverData == null || !serverData.ContainsKey("iv") || !serverData.ContainsKey("vault"))
            {
                Console.WriteLine("Server-filen saknar iv och/eller vault, eller är null.");
                return;
            }

            byte[] iv;
            byte[] encryptedBytes;
            try
            {
                iv = Convert.FromBase64String(serverData["iv"]);
                encryptedBytes = Convert.FromBase64String(serverData["vault"]);
            }
            catch
            {
                Console.WriteLine("Server-filens iv eller vault är inte i giltigt Base64-format.");
                return;
            }

            Console.WriteLine("Ange master password: ");
            string masterPassword = Console.ReadLine() ?? "";

            byte[] vaultKeyOld = DeriveVaultKey(secretKey, masterPassword);

            Dictionary<string, string> vault;
            try
            {
                byte[] decryptedBytes = DecryptVault(encryptedBytes, vaultKeyOld, iv);
                string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);

                vault = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedJson)
                        ?? new Dictionary<string, string>();
            }
            catch
            {
                Console.WriteLine("Dekrypteringen misslyckades, angett rätt lösenord?");
                return;
            }

            Console.WriteLine("Ange nytt master password: ");
            string masterPasswordNew = Console.ReadLine() ?? "";

            if (string.IsNullOrEmpty(masterPasswordNew))
            {
                Console.WriteLine("Du måste ange ett nytt lösenord");
                return;
            }

            byte[] vaultKeyNew = DeriveVaultKey(secretKey, masterPasswordNew);

            string vaultToJson = JsonSerializer.Serialize(vault);
            byte[] vaultBytes = Encoding.UTF8.GetBytes(vaultToJson);
            byte[] encryptedBytesNew = EncryptVault(vaultBytes, vaultKeyNew, iv);

            serverData["vault"] = Convert.ToBase64String(encryptedBytesNew);

            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverData));
        }
        //auto-genererar slumpmässigt lösenord på 20 tecken
        static string autoGeneratePassword()
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var autoPassword = new StringBuilder(20);

            byte[] autoBytes = new byte[20];
            RandomNumberGenerator.Fill(autoBytes);

            for (int i = 0; i < 20; i++)
                autoPassword.Append(chars[autoBytes[i] % chars.Length]);

            string autoPasswordNew = autoPassword.ToString();

            return autoPasswordNew;
        }

        //Skapar vault keyn som används för att kryptera och dekryptera. Vi valde 10000 iterations för extra säkerhet, stod att det minst skulle vara 1000. 
        static byte[] DeriveVaultKey(byte[] secretKey, string masterPassword)
        {


            using var pbkdf2 = new Rfc2898DeriveBytes(
                masterPassword,
                secretKey,
                10000,
                HashAlgorithmName.SHA256);

            return pbkdf2.GetBytes(32);
        }

        //Krypterar valtet med aes. 
        static byte[] EncryptVault(byte[] vaultBytes, byte[] vaultKey, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Key = vaultKey;
            aes.IV = iv;

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(vaultBytes, 0, vaultBytes.Length);
        }

        //Dekrypterar valtet med aes
        static byte[] DecryptVault(byte[] vaultBytes, byte[] vaultKey, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Key = vaultKey;
            aes.IV = iv;

            using ICryptoTransform decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(vaultBytes, 0, vaultBytes.Length);
        }
    }
}