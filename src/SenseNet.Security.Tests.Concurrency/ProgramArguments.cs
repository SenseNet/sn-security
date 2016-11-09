using CmdLine;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SenseNet.Security.Tests.Concurrency
{
    [CommandLineArguments(Program = "SenseNet.Security.Tests.Concurrency", Title = "SenseNet.Security.Tests.Concurrency", Description = "Concurrency tests for SenseNet.Security component.")]
    internal class ProgramArguments
    {
        public static ProgramArguments Parse()
        {
            ProgramArguments arguments = null;
            try
            {
                arguments = CommandLine.Parse<ProgramArguments>();
            }
            catch (CommandLineException exception)
            {
                Console.WriteLine(exception.ArgumentHelp.Message);
                Console.WriteLine(exception.ArgumentHelp.GetHelpText(Console.BufferWidth));
                if (Debugger.IsAttached)
                {
                    Console.Write("Press <enter> to exit...");
                    Console.ReadLine();
                }
                return null;
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception);
                if (Debugger.IsAttached)
                {
                    Console.Write("Press <enter> to exit...");
                    Console.ReadLine();
                }
                return null;
            }
            return arguments;
        }

        [CommandLineParameter(Command = "?", Default = false, Description = "Show Help", Name = "Help", IsHelp = true)]
        public bool Help { get; set; }

        //[CommandLineParameter(Name = "agents", ParameterIndex = 1, Required = false, Description = "Specifies the number of simultaneous agents.", Default = 3)]
        //public int Agents { get; set; }
        [CommandLineParameter(Command = "test", ParameterIndex = 1, Required = true, Description = "Name of the test to run.")]
        public string TestName { get; set; }
        [CommandLineParameter(Command = "agents", ParameterIndex = 2, Required = false, Description = "Specifies the number of simultaneous agents.", Default = 3)]
        public int Agents { get; set; }

        //[CommandLineParameter(Name = "destination", ParameterIndex = 2, Description = "Specifies the directory and/or filename for the new file(s).")]
        //public string Destination { get; set; }

        //[CommandLineParameter(Command = "A", Required = true, Description = "Indicates an ASCII text file")]
        //public bool ASCIITextFile { get; set; }

        //[CommandLineParameter(Command = "B", Description = "Indicates a binary file.")]
        //public bool BinaryFile { get; set; }

        // etc. 
    }
}
