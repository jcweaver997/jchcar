using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace jchcar
{
    internal class Program
    {
        Stopwatch sw = new Stopwatch();
        
        public static void Main(string[] args)
        {
            //CarControl c = new CarControl();
            //c.Start();
            WifiCracking wc = new WifiCracking();
            var wifis = wc.Scan();
            foreach (var wifi in wifis)
            {
                Console.WriteLine(wifi.BSSID);
                if (wifi.BSSID.Equals("A0:04:60:A6:B0:0C"))
                {
                    Console.WriteLine("found");
                    wc.CrackWPA2(wifi);
                }
            }
            Console.WriteLine("done");
            
        }   
    }
}