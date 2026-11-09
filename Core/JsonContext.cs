using System.Text.Json.Serialization;

namespace MCPGuard.Core;

public sealed class AuditIssue
{
    public string Severity { get; set; } = "";
    public string Rule { get; set; } = "";
    public string Target { get; set; } = "";
    public string Detail { get; set; } = "";
}

public sealed class AuditTarget
{
    public string Path { get; set; } = "";
    public bool Exists { get; set; }
    public string Status { get; set; } = "";
    public AuditIssue[] Issues { get; set; } = Array.Empty<AuditIssue>();
}

public sealed class AuditSummary
{
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Info { get; set; }
}

public sealed class AuditReport
{
    public string Tool { get; set; } = "MCP-Guard";
    public string Version { get; set; } = "1.0.0";
    public string GeneratedAt { get; set; } = "";
    public int RiskScore { get; set; }
    public int IssueCount { get; set; }
    public AuditTarget[] Targets { get; set; } = Array.Empty<AuditTarget>();
    public AuditSummary Summary { get; set; } = new AuditSummary();
}

[JsonSerializable(typeof(AuditReport))]
[JsonSerializable(typeof(AuditTarget))]
[JsonSerializable(typeof(AuditIssue))]
[JsonSerializable(typeof(AuditSummary))]
public partial class JsonContext : JsonSerializerContext
{
}
