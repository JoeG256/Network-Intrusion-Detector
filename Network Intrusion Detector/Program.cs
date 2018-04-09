using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
//SHARPPCAP LIBRARY FROM https://www.codeproject.com/Articles/12458/SharpPcap-A-Packet-Capture-Framework-for-NET - ACCESSED 03/02/2018
using SharpPcap; 
using PacketDotNet; 
//END

//TODO:
// REWRITE PACKET CAPTURE USING SHARPPCAP LIBRARY - DONE
// STORE PACKET BASELINE
// COMPARE & DETECT <- LIKELY HARDEST
// LOOK INTO SHARPPCAP FEATURES FOR NETWORK INTRUSION DETECTION

namespace Network_Intrusion_Detector
{
    //CLASS FOR BASELINE SAVING
    class BaselineActivity
    {
        private string Priv_KEY;
        private string Priv_ETH;
        private string Priv_IP;
        private string Priv_TCP_UDP;
        public void SaveText(System.IO.TextWriter Output_S)
        {
            Output_S.WriteLine(Priv_KEY);
            Output_S.WriteLine(Priv_ETH);
            Output_S.WriteLine(Priv_IP);
            Output_S.WriteLine(Priv_TCP_UDP);
        }
        public BaselineActivity(System.IO.TextReader Input_S)
        {
            Priv_KEY = Input_S.ReadLine();
            Priv_ETH = Input_S.ReadLine();
            Priv_IP = Input_S.ReadLine();
            Priv_TCP_UDP = Input_S.ReadLine();
        }
        public BaselineActivity(string KEY, string ETHERNET, string IP, string TCP_UDP)
        {
            Priv_KEY = KEY;
            Priv_ETH = ETHERNET;
            Priv_IP = IP;
            Priv_TCP_UDP = TCP_UDP;
        }
    }

    class Program
    {
        // DICTIONARY
        
        private static Dictionary<string, BaselineActivity> BaselineDict; //Defines dictionary
        static Program()
        {
            BaselineDict = new Dictionary<string, BaselineActivity>();
        }
        static int newDictionaryEntryValue = 1;
        static bool TextOutput = true;
        static bool CompareOrBaseline = false;
        static int PacketCounter = 0;

        static void Main(string[] args)
        {
            Program DictionaryInitializer = new Program(); //Initializes dictionary
            CaptureDeviceList DeviceList = CaptureDeviceList.Instance;
            if (DeviceList.Count < 1)
            {
                Console.WriteLine("No devices found");
            }
            else
            {
                foreach (ICaptureDevice device in DeviceList)
                {
                    Console.WriteLine(device.ToString());
                }
            }
            Console.WriteLine("Menu:");
            Console.WriteLine("Press the corrosponding number to select your choice");
            Console.WriteLine("1 - Gather baseline with text display");
            Console.WriteLine("2 - Gather baseline without text display");
            Console.WriteLine("3 - Compare baseline to live packets");
            ConsoleKeyInfo KeyPress = Console.ReadKey();
            switch (KeyPress.KeyChar)
            {
                case ('1'):
                    TextOutput = true;
                    BaseLineNetActivity(DeviceList);
                    break;
                case ('2'):
                    TextOutput = false;
                    BaseLineNetActivity(DeviceList);
                    break;
                case ('3'):
                    CompareActivity(DeviceList);
                    break;
            }  
            Console.WriteLine("COMPLETE. Press any key to exit");
            Console.ReadLine();
            SaveStream("Baseline_Network_Activity.txt"); //Save to text file
        }

        static void BaseLineNetActivity(CaptureDeviceList DeviceList)
        {
            CompareOrBaseline = false;
            Console.WriteLine();
            Console.WriteLine("BASELINE:");
            PacketCollect(DeviceList);
        }

        static void CompareActivity(CaptureDeviceList DeviceList)
        {
            CompareOrBaseline = true;
            Console.WriteLine();
            Console.WriteLine("LIVE COMPARISON:");
            PacketCollect(DeviceList);
        }

        //CODE FROM https://www.codeproject.com/Articles/12458/SharpPcap-A-Packet-Capture-Framework-for-NET - ACCESSED 03/02/2018 - HEAVILY MODIFIED
        static void PacketCollect(CaptureDeviceList DeviceList)
        {
            int BaselineLimiter = 1000; //CHANGE THIS VALUE TO DETERMINE SIZE OF BASELINE
            // Extract a device from the list
            ICaptureDevice device = DeviceList[0]; //<- VALUE OF 0 WILL USE FIRST DEVICE
            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(Device_OnPacketArrival);
            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            if(CompareOrBaseline == false)
            {
                // Open the device for capturing
                // tcpdump filter to capture only TCP/IP packets
                Console.WriteLine("-- Listening on {0}, collecting " + BaselineLimiter + " packets. Press any key to terminate early.",device.Description);
                // Start capturing packets
                while(PacketCounter < BaselineLimiter) 
                {
                    RawCapture rawPacket = null;
                    rawPacket = device.GetNextPacket(); //get the next packet
                    if(rawPacket != null) //if there's actually a packet there
                    {
                        var decodedPacket = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data); //parse the packet 
                        if (TextOutput == true)
                        {
                            Console.WriteLine("PACKET BEGIN...");
                            Console.WriteLine(decodedPacket.ToString());
                            AddToList(decodedPacket.ToString());
                            Console.WriteLine("...PACKET END");
                        }
                        else if (TextOutput == false)
                        {
                            AddToList(decodedPacket.ToString()); //add to dictionary
                        }
                        ++PacketCounter;
                    }
                }     
            }
            else if(CompareOrBaseline == true)
            {
                device.Capture();
                device.Close(); //never called
            }
        }
        //END CODE

        private static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
                //if (TextOutput == true)
                //{
                //    Console.WriteLine("PACKET BEGIN...");
                //    var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                //    Console.WriteLine(packet.ToString());
                //    AddToList(packet.ToString());
                //    Console.WriteLine("...PACKET END");
                //}
                //ANALYSIS LOGIC, COMPARE AGAINST BASELINE
                var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
           
        }

        static void AddToList(string packet) 
        {
            string eth = "", ip = "", tcp_udp = "";
            string[] ListArraySplit = Regex.Matches(packet, @"\[.*?\]").Cast<Match>().Select(m => m.Value).ToArray(); //LINE OF CODE FROM https://stackoverflow.com/questions/15421651/splitting-a-string-in-c-sharp - ACCESSED 26/02/2018
            for (int i = 0; i < ListArraySplit.Count(); ++i)
            {
                switch(i)
                {
                    case 0:
                        eth = ListArraySplit[0];
                        break;
                    case 1:
                        ip = ListArraySplit[1];
                        break;
                    case 2:
                        tcp_udp = ListArraySplit[2];
                        break;
                }
            }
            if (eth == "")
                eth = "NULL";
            if (ip == "")
                eth = "NULL";
            if (tcp_udp == "")
                tcp_udp = "NULL";
            if(CompareOrBaseline == false)
                AddBaseline(eth, ip, tcp_udp);
        }
    
        static void AddBaseline(string eth, string ip, string tcp_udp)
        {
            string newBaselineValueNumber = newDictionaryEntryValue.ToString();
            BaselineActivity newBaseline = new BaselineActivity(newBaselineValueNumber, eth, ip, tcp_udp); //Add to class
            BaselineDict.Add(newBaselineValueNumber, newBaseline); //Add to dictionary
            newDictionaryEntryValue = newDictionaryEntryValue + 1; //Increment key that's used to find specific baseline values        
        }

        //LOAD AND SAVE FUNCTIONALITY - MAKE SURE THAT IF A FILE DOESN'T EXIST THE PROGRAM CREATES ONE
        static void LoadStream(string filename)
        {
            System.IO.StreamReader Input_S = null;
            try
            {
                Input_S = new System.IO.StreamReader(filename);
                LoadText(Input_S);
            }
            catch (Exception e)
            {
                throw e;
            }
            finally
            {
                if (Input_S != null)
                    Input_S.Close();
            }
        }
        static void LoadText(System.IO.TextReader Input_S)
        {
            try
            {

                int listcount = int.Parse(Input_S.ReadLine());
                for (int c = 1; c <= listcount; c++) //need to do things here <------------------ VERY IMPORTANT
                {

                }
            }
            catch (Exception e)
            {
                throw e;
            }
            finally
            {
                if (Input_S != null)
                    Input_S.Close();
            }
        }
        static void SaveStream(string filename)
        {
            System.IO.StreamWriter Output_S = null;
            try
            {
                Output_S = new System.IO.StreamWriter(filename); 
                SaveText(Output_S); 
            }
            catch (Exception e)
            {
                throw e;
            }
            finally
            {
                if (Output_S != null)
                    Output_S.Close();
            }
        }
        static void SaveText(System.IO.TextWriter Output_S)
        {
            try
            {
                Output_S.WriteLine(BaselineDict.Count);
                foreach (BaselineActivity a in BaselineDict.Values) 
                {
                    a.SaveText(Output_S); 
                }
            }
            catch (Exception e)
            {
                throw e;
            }
            finally
            {
                if (Output_S != null)
                    Output_S.Close();
            }
        }

       
    }
}
