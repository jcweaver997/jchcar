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
            CarControl c = new CarControl();
            new Thread(()=>
            {
                c.Start();
            }).Start();
            WifiCracking wc = new WifiCracking();
            wc.Start();
            
        }   
    }
}