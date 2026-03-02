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

        }
    }
}
