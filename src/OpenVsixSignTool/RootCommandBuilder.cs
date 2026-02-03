using System.CommandLine;

namespace OpenVsixSignTool
{
    internal static class RootCommandBuilder
    {
        public static RootCommand Build()
        {
            var rootCommand = new RootCommand("OpenVsixSignTool is a command-line tool for signing a VSIX file using a certificate or Azure Key Vault.");
            rootCommand.Subcommands.Add(SignCommand.Create());
            rootCommand.Subcommands.Add(UnsignCommand.Create());
            return rootCommand;
        }
    }
}
