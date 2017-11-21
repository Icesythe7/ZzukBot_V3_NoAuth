using System;
using System.Diagnostics;

namespace BotLauncher
{
    internal class Program
    {
        private static void Main()
        {

            var start = new ProcessStartInfo
            {
                FileName = "ZzukBot.exe",
                WorkingDirectory = "Internal\\"
            };
            Process.Start(start);
            Environment.Exit(0);
        }
    }
}