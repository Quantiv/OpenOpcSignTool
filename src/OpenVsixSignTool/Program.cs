namespace OpenVsixSignTool
{
    static class Program
    {
        internal static int Main(string[] args)
        {
            var rootCommand = RootCommandBuilder.Build();
            return rootCommand.Parse(args).Invoke();
        }
    }
}
