using System;
using System.CommandLine;
using System.IO;
using OpenVsixSignTool.Core;

namespace OpenVsixSignTool
{
    internal static class UnsignCommand
    {
        public static Command Create()
        {
            var command = new Command("unsign", "Removes all signatures from a VSIX package.");

            var vsixFileArgument = new Argument<FileInfo>("vsixFile")
            {
                Description = "The VSIX file to sign.",
                Arity = ArgumentArity.ExactlyOne
            };
            command.Arguments.Add(vsixFileArgument);

            command.SetAction(parseResult =>
            {
                var vsixFile = parseResult.GetValue(vsixFileArgument);
                var vsixFilePath = vsixFile.FullName;
                if (!File.Exists(vsixFilePath))
                {
                    Console.Error.WriteLine("Specified VSIX file does not exist.");
                    return 2;
                }
                using (var package = OpcPackage.Open(vsixFilePath, OpcPackageFileMode.ReadWrite))
                {
                    var unsigned = false;
                    foreach (var signature in package.GetSignatures())
                    {
                        unsigned = true;
                        signature.Remove();
                    }
                    if (!unsigned)
                    {
                        Console.Error.WriteLine("Specified VSIX is not signed.");
                        return 2;
                    }
                    Console.Out.WriteLine("The unsigning operation is complete.");
                    return 0;
                }
            });

            return command;
        }
    }
}
