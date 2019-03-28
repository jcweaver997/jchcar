using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace jchcar
{
    public class CarControl
    {
        Stopwatch sw = new Stopwatch();
        

        public CarControl()
        {
            init_rchcar();
        }
        
        ~CarControl()
        {
            close_rchcar();
        }

        public void Start()
        {
            JcRobotNetworking jcnet = new JcRobotNetworking(JcRobotNetworking.ConnectionType.Robot,OnMessageReceive);
            jcnet.Connect(1296);
            Watchdog();
        }

        private void Watchdog()
        {
            sw.Start();
            while (true)
            {
                if (sw.ElapsedMilliseconds>500)
                {
                    set_drive(0);
                    set_servo(0.5f);
                }
                Thread.Sleep(20);
            }
        }

        [DllImport ("jchcar.so")]
        private static extern void init_rchcar ();
        
        [DllImport ("jchcar.so")]
        private static extern void set_servo(float p);
        
        [DllImport ("jchcar.so")]
        private static extern void set_drive(float p);
        
        [DllImport ("jchcar.so")]
        private static extern void close_rchcar();
        
        private void OnMessageReceive(JcRobotNetworking.Command c)
        {
            sw.Restart();
            switch (c.commandID)
            {
                case 1:
                    set_servo(BitConverter.ToSingle(c.param,0));
                    break;
                case 2:
                    set_drive(BitConverter.ToSingle(c.param,0));
                    break;
            }

        }
    }
}