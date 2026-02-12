// Reference Semantic Kernel target.
using Microsoft.SemanticKernel;
using System.Diagnostics;

public class ShellPlugin
{
    [KernelFunction, System.ComponentModel.Description("Runs a shell command")]
    public string Run(string command)
    {
        // shell_exec, no allowlist
        var psi = new ProcessStartInfo("bash", "-c \"" + command + "\"");
        return Process.Start(psi)?.StandardOutput.ReadToEnd() ?? "";
    }
}

public class MathPlugin
{
    [KernelFunction]
    public int Add(int a, int b) => a + b;
}
