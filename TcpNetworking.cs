using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace jchcar
{
    public class TcpNetworking
    {
        private ConnectionType connectionType;
        private IPEndPoint remoteEP;
        private IPEndPoint localEP;
        private TcpListener server;
        private TcpClient client;
        private OnMessageRecieve onMessageRecieve;
        private Thread serverAcceptThread;
        private Thread receiveThread;
        private StreamReader sr;
        private StreamWriter sw;

        public delegate void OnMessageRecieve(string m);
        
        
        private enum ConnectionType
        {
            Client,Server
        }
        
        
        
        public TcpNetworking(IPEndPoint ep, OnMessageRecieve onMessageRecieve = null)
        {
            this.onMessageRecieve = onMessageRecieve;
            if (ep.Address.Equals(IPAddress.Any))
            {
                ServerInit(ep);
            }
            else
            {
                ClientInit(ep);
            }
        }

        private void ServerInit(IPEndPoint ep)
        {
            connectionType = ConnectionType.Server;
            localEP = ep;
        }

        private void ClientInit(IPEndPoint ep)
        {
            connectionType = ConnectionType.Client;
            remoteEP = ep;

        }

        public void Start()
        {
            if (connectionType == ConnectionType.Server)
            {
                ServerStart();
            }
            else
            {
                ClientStart();
            }
        }

        private void ServerAccept()
        {
            while (true)
            {
                Console.WriteLine("Waiting for new client ");
                TcpClient newclient = server.AcceptTcpClient();
                Console.WriteLine("New TCP Client at "+newclient.Client.RemoteEndPoint);
                client?.Close();
                client = newclient;
                sr = new StreamReader(client.GetStream());
                sw = new StreamWriter(client.GetStream());
                receiveThread?.Abort();
                receiveThread = new Thread(ReceiveThread);
                receiveThread.Start();
            }
        }

        private void ReceiveThread()
        {
            Console.WriteLine("started rec");
            if (onMessageRecieve == null) return;
            
            string message;
            while (true)
            {
                Console.WriteLine("waiting mess");
                message = sr.ReadLine();
                Console.WriteLine("got something");
                if (message==null)
                {
                    Console.WriteLine("bad?");
                    break;
                }
                Console.WriteLine("message "+message);
                onMessageRecieve(message);
            }
        }

        private void ServerStart()
        {
            server = new TcpListener(localEP);
            server.Start();
            serverAcceptThread = new Thread(ServerAccept);
            serverAcceptThread.Start();
        }

        private void ClientStart()
        {
            client = new TcpClient();
            client.Connect(remoteEP);
            sr = new StreamReader(client.GetStream());
            sw = new StreamWriter(client.GetStream());
            receiveThread?.Abort();
            receiveThread = new Thread(ReceiveThread);
            receiveThread.Start();

        }

        public void Close()
        {
            client?.Close();
            serverAcceptThread?.Abort();
            receiveThread?.Abort();
        }

        public void Send(string message)
        {
            sw?.WriteLine(message);
            sw?.Flush();
        }
        
        
        
        
        
    }
}