using SenseNet.Security.Messaging;
using SenseNet.Security.Tests;
using SenseNet.Security.Tests.TestPortal;
using System;
using System.Collections.Generic;
using SenseNet.Security.Data;

namespace SenseNet.Security.TestConsole
{
    internal class Program
    {
        // ReSharper disable once UnusedParameter.Local
        private static void Main(string[] args)
        {
            //---- Ensure test data
            var entities = SystemStartTests.CreateTestEntities();
            var groups = SystemStartTests.CreateTestGroups();
            var memberships = Tools.CreateInMemoryMembershipTable(groups);
            var aces = SystemStartTests.CreateTestAces();
            var storage = new DatabaseStorage { Aces = aces, Memberships = memberships, Entities = entities };

            //---- Start the system
            Context.StartTheSystem(new MemoryDataProvider(storage));

            //---- Start the request
            var context = new Context(TestUser.User1);


            //======== Test
            var channel = context.Security.MessageProvider;
            channel.MessageReceived += MessageReceived;
            channel.SendException += SendException;
            channel.ReceiveException += ReceiveException;

            Console.WriteLine("S<enter>: sent test, <enter>: clear screen, X<enter>: exit...");
            Console.WriteLine("Receiver: " + channel.ReceiverName);
            while (true)
            {
                var s = Console.ReadLine();
                if ("S" == s?.ToUpper())
                {
                    channel.SendMessage(new PingMessage());
                    Console.WriteLine("A ping message was sent.");
                    var activity = new Messaging.SecurityMessages.SetAclActivity(
                        new[] { new AclInfo(1) },
                        new List<int>(),
                        new List<int>()
                        );
                    activity.Execute(context.Security);
                }
                else if ("X" == s?.ToUpper())
                    break;
                else if ("" == s)
                {
                    Console.Clear();
                    Console.WriteLine("S<enter>: sent test, <enter>: clear screen, X<enter>: exit...");
                    Console.WriteLine("Receiver: " + channel.ReceiverName);
                }
            }

            channel.ShutDown();

        }

        private static void MessageReceived(object sender, MessageReceivedEventArgs args)
        {
            var message = args.Message;
            Console.WriteLine("MessageReceived: {0} from {1}", args.Message.GetType().Name, message.Sender.ComputerID);
        }

        private static void ReceiveException(object sender, ExceptionEventArgs args)
        {
            Console.WriteLine("ReceiveException: " + args.Message);
        }

        private static void SendException(object sender, ExceptionEventArgs args)
        {
            Console.WriteLine("SendException: " + args.Exception.Message);
        }


        private static int Id(string name)
        {
            return Tools.GetId(name);
        }

    }
}
