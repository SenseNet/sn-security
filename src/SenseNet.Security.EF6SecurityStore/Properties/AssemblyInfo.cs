using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: InternalsVisibleTo("SenseNet.Security.Tests")]

#if DEBUG
[assembly: AssemblyTitle("SenseNet.Security.EF6SecurityStore (Debug)")]
#else
[assembly: AssemblyTitle("SenseNet.Security.EF6SecurityStore (Release)")]
#endif

[assembly: AssemblyDescription("Security component Entity Framework db provider")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("Sense/Net Inc.")]
[assembly: AssemblyProduct("SenseNet.Security.EF6SecurityStore")]
[assembly: AssemblyCopyright("Copyright © Sense/Net Inc.")]
[assembly: AssemblyTrademark("Sense/Net Inc.")]
[assembly: AssemblyCulture("")]

[assembly: AssemblyVersion("3.0.1.0")]
[assembly: AssemblyFileVersion("3.0.1.0")]
[assembly: AssemblyInformationalVersion("3.0.1")]

[assembly: ComVisible(false)]
[assembly: Guid("ecb674cd-59ec-43a5-b7a8-31aaab39a520")]