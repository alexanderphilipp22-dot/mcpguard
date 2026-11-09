using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using MCPGuard.Core;

namespace MCPGuard;

public static class Program
{
    public const string Version = "1.0.0";

    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 0;
        }

        switch (args[0])
        {
            case "audit":
                return RunAudit(args.AsSpan(1));
            case "lock":
                return RunProtect(args.AsSpan(1), lockMode: true);
            case "unlock":
                return RunProtect(args.AsSpan(1), lockMode: false);
            case "help":
            case "--help":
            case "-h":
                PrintUsage();
                return 0;
            case "version":
            case "--version":
            case "-v":
                Console.WriteLine($"mcpguard {Version}");
                return 0;
            default:
                Console.Error.WriteLine($"error: unknown command '{args[0]}'");
                PrintUsage();
                return 2;
        }
    }

    private static int RunAudit(ReadOnlySpan<string> args)
    {
        bool json = HasFlag(args, "--json");
        string? config = GetOption(args, "--config");

        string[] paths = string.IsNullOrEmpty(config)
            ? ConfigLocator.GetDefaultPaths()
            : new[] { config! };

        AuditReport report = AuditEngine.Audit(paths);

        if (json)
            Console.WriteLine(JsonSerializer.Serialize(report, JsonContext.Default.AuditReport));
        else
            PrintReport(report);

        return report.RiskScore == 0 ? 0 : 1;
    }

    private static int RunProtect(ReadOnlySpan<string> args, bool lockMode)
    {
        string[] paths = ResolvePaths(args);
        if (paths.Length == 0)
        {
            Console.Error.WriteLine(lockMode
                ? "error: no MCP config files found to lock."
                : "error: no MCP config files found to unlock.");
            return 1;
        }

        int failures = 0;
        foreach (string p in paths)
        {
            string msg;
            bool ok = lockMode ? FileProtector.Lock(p, out msg) : FileProtector.Unlock(p, out msg);
            if (ok)
                Console.WriteLine(msg);
            else
            {
                Console.Error.WriteLine("error: " + msg);
                failures++;
            }
        }
        return failures == 0 ? 0 : 1;
    }

    private static string[] ResolvePaths(ReadOnlySpan<string> args)
    {
        string? config = GetOption(args, "--config");
        if (!string.IsNullOrEmpty(config))
            return new[] { config! };

        var existing = new List<string>(8);
        foreach (string p in ConfigLocator.GetDefaultPaths())
            if (File.Exists(p))
                existing.Add(p);
        return existing.ToArray();
    }

    private static void PrintReport(AuditReport report)
    {
        Console.WriteLine($"MCP-Guard {report.Version} - Audit Report");
        Console.WriteLine($"Generated : {report.GeneratedAt}");
        Console.WriteLine($"Risk Score: {report.RiskScore}/100   Issues: {report.IssueCount}");
        Console.WriteLine(new string('-', 64));

        foreach (AuditTarget t in report.Targets)
        {
            Console.WriteLine();
            Console.WriteLine($"Config: {t.Path}");
            Console.WriteLine($"Status: {t.Status}");

            if (t.Issues.Length == 0)
            {
                Console.WriteLine("  [ok] no issues");
                continue;
            }

            foreach (AuditIssue i in t.Issues)
            {
                Console.WriteLine($"  [{i.Severity.ToUpperInvariant()}] {i.Rule}");
                Console.WriteLine($"        {i.Target}: {i.Detail}");
            }
        }

        AuditSummary s = report.Summary;
        Console.WriteLine();
        Console.WriteLine($"Summary: {s.Critical} critical, {s.High} high, {s.Medium} medium, {s.Low} low, {s.Info} info");
        Console.WriteLine($"Verdict: {Verdict(report.RiskScore)}");
    }

    private static string Verdict(int riskScore)
        => riskScore >= 50 ? "CRITICAL - isolate and remediate immediately"
         : riskScore >= 20 ? "HIGH - requires attention"
         : riskScore >= 5 ? "MODERATE - review findings"
         : "LOW - no significant risk";

    private static bool HasFlag(ReadOnlySpan<string> args, string name)
    {
        foreach (string a in args)
            if (string.Equals(a, name, StringComparison.Ordinal))
                return true;
        return false;
    }

    private static string? GetOption(ReadOnlySpan<string> args, string name)
    {
        string eq = name + "=";
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (string.Equals(arg, name, StringComparison.Ordinal))
            {
                if (i + 1 < args.Length)
                {
                    string next = args[i + 1];
                    if (!next.StartsWith("--", StringComparison.Ordinal))
                        return next;
                }
                return string.Empty;
            }

            if (arg.StartsWith(eq, StringComparison.Ordinal))
                return arg.Substring(eq.Length);
        }
        return null;
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            "MCP-Guard (mcpguard) - offline security suite for local MCP environments\n" +
            "\n" +
            "Usage:\n" +
            "  mcpguard audit  [--config <path>] [--json]   Scan MCP configs for risks\n" +
            "  mcpguard lock   [--config <path>]            Write-protect MCP configs (OS-level)\n" +
            "  mcpguard unlock [--config <path>]            Remove write protection for manual edits\n" +
            "  mcpguard version                             Print version\n" +
            "\n" +
            "Options:\n" +
            "  --config <path>   Path to a specific config file (default: auto-detect)\n" +
            "  --json            Emit the audit result as JSON\n" +
            "\n" +
            "Detected configs (when no --config is given):\n" +
            "  Claude Desktop, Cursor, VS Code, and any path set in MCP_GUARD_CONFIG");
    }
}
