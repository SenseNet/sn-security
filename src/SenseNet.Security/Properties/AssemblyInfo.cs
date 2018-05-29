using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: InternalsVisibleTo("SenseNet.Security.Tests")]
[assembly: InternalsVisibleTo("SenseNet.Security.Tests.Concurrency")]

#if DEBUG
[assembly: AssemblyTitle("SenseNet.Security (Debug)")]
#else
[assembly: AssemblyTitle("SenseNet.Security (Release)")]
#endif

[assembly: AssemblyDescription("Security component for sensenet")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("Sense/Net Inc.")]
[assembly: AssemblyProduct("SenseNet.Security")]
[assembly: AssemblyCopyright("Copyright © Sense/Net Inc.")]
[assembly: AssemblyTrademark("Sense/Net Inc.")]
[assembly: AssemblyCulture("")]

[assembly: AssemblyVersion("2.4.0.0")]
[assembly: AssemblyFileVersion("2.4.0.0")]
[assembly: AssemblyInformationalVersion("2.4.0")]

[assembly: ComVisible(false)]
[assembly: Guid("4d39314d-72ed-4f63-90ed-a60b458495fa")]