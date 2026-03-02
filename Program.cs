using System.IO;



namespace Lösenordshanterare
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string clientPath = "client.txt";
            
            string serverPath = "server.txt";

            if (!File.Exists(clientPath))
            {
                File.WriteAllText(clientPath, ""); // Skapar en tom fil
                Console.WriteLine($"Klientfil skapad på: {clientPath}");
}

            // Skapa serverfilen om den inte finns
            if (!File.Exists(serverPath))
            {
                File.WriteAllText(serverPath, "");
    Console.WriteLine($"Serverfil skapad på: {serverPath}");
            }

        }
    }
}
