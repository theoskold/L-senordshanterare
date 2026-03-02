using System.IO;



namespace Lösenordshanterare
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Ange sökväg för klientfil (t.ex. client.txt):");
            string clientPath = Console.ReadLine();

            Console.WriteLine("Ange sökväg för serverfil (t.ex. server.txt):");
            string serverPath = Console.ReadLine();

            if (!File.Exists(clientPath))
            {
                File.WriteAllText(clientPath, ""); // Skapar en tom fil
                [cite_start] Console.WriteLine($"Klientfil skapad på: {clientPath}"); [cite: 150]
}

            // Skapa serverfilen om den inte finns
            if (!File.Exists(serverPath))
            {
                [cite_start] File.WriteAllText(serverPath, ""); [cite: 138]
    Console.WriteLine($"Serverfil skapad på: {serverPath}");
            }

        }
    }
}
