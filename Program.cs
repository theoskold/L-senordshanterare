using System.IO;
using System.Security.Cryptography;


namespace Lösenordshanterare
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string clientPath = "client.txt";
            
            string serverPath = "server.txt";

            
            if (!File.Exists(clientPath) || new FileInfo(clientPath).Length == 0)
            {
               
                
                byte[] keyBytes = new byte[32];
                RandomNumberGenerator.Fill(keyBytes);
                string secretKey = Convert.ToBase64String(keyBytes);
                File.WriteAllText(clientPath, secretKey );
                Console.WriteLine("secret key är skapad och fil är skapad");

}

            // Skapa serverfilen om den inte finns
            if (!File.Exists(serverPath) || new FileInfo(serverPath).Length == 0)
            {
                byte[] vectorBytes = new byte[16];
                RandomNumberGenerator.Fill(vectorBytes);
                string iv = Convert.ToBase64String(vectorBytes);
                File.WriteAllText(serverPath, iv);
                Console.WriteLine("iv är skapad och fil är skapad");
            }

            // Skapar ett tomt valv (steg 4 i DFD)

            Dictionary<string, string> vault = new Dictionary<string, string>();
            vault.Add("netflix.com", "hemligt123");
            vault.Add("google.com", "lösenord456");

            // Kontrollera innehållet med en foreach-loop
            foreach (var item in vault)
            {
                // Använd egenskaperna Key och Value för att skriva ut informationen
                Console.WriteLine($"Konto: {item.Key}, Lösenord: {item.Value}");
            }

        }
    }
}
