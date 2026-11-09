using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace MCPGuard.Core;

/// <summary>
/// Span-based rule engine. Executes the five core checks:
///   1. Unpinned execution   (npx -y / uvx without exact version pin)
///   2. Toxic pair           (file-write + command-exec / git servers)
///   3. Secret leakage       (hardcoded keys in env blocks)
///   4. Unicode injection    (invisible tag / control / bidi code points)
///   5. Over-privileged paths (drive roots / home dirs)
/// </summary>
public static class AuditEngine
{
    private const string SevCritical = "critical";
    private const string SevHigh = "high";
    private const string SevMedium = "medium";
    private const string SevLow = "low";
    private const string SevInfo = "info";

    private static readonly string[] WriteMarkers =
    {
        "filesystem", "write", "writefile", "writetext", "createfile", "save", "--write", "-w"
    };

    private static readonly string[] ExecMarkers =
    {
        "exec", "shell", "terminal", "bash", "cmd", "powershell", "pwsh", "git", "eval", "subprocess", "docker", "run-command"
    };

    private static readonly string[] SecretPrefixes =
    {
        "sk-", "sk_", "AIza", "ghp_", "gho_", "ghu_", "github_pat_",
        "xoxb-", "xoxp-", "xoxa-", "AKIA", "ASIA", "-----BEGIN", "eyJ",
        "ssh-rsa", "ssh-ed25519", "ssh-dss", "glpat-", "gpg-"
    };

    private static readonly string[] SecretKeyNames =
    {
        "key", "token", "secret", "password", "passwd", "apikey", "api_key", "auth", "credential", "private", "access"
    };

    [Flags]
    private enum Caps
    {
        None = 0,
        Write = 1,
        Exec = 2,
    }

    public static AuditReport Audit(IReadOnlyList<string> configPaths)
    {
        var targets = new List<AuditTarget>(configPaths.Count);
        var summary = new AuditSummary();
        int issueCount = 0;

        foreach (string path in configPaths)
        {
            AuditTarget target = ScanTarget(path);
            targets.Add(target);

            foreach (AuditIssue issue in target.Issues)
            {
                AddToSummary(summary, issue.Severity);
                issueCount++;
            }
        }

        return new AuditReport
        {
            GeneratedAt = DateTimeOffset.UtcNow.ToString("O"),
            Targets = targets.ToArray(),
            Summary = summary,
            IssueCount = issueCount,
            RiskScore = ComputeRiskScore(summary),
        };
    }

    private static AuditTarget ScanTarget(string path)
    {
        var target = new AuditTarget { Path = path };
        var issues = new List<AuditIssue>();

        if (!File.Exists(path))
        {
            target.Exists = false;
            target.Status = "not-found";
            target.Issues = issues.ToArray();
            return target;
        }

        target.Exists = true;

        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex)
        {
            target.Status = "unreadable";
            issues.Add(new AuditIssue { Severity = SevInfo, Rule = "unreadable", Target = path, Detail = ex.Message });
            target.Issues = issues.ToArray();
            return target;
        }

        target.Status = "scanned";

        if (text.Length == 0)
        {
            issues.Add(new AuditIssue { Severity = SevInfo, Rule = "empty-config", Target = path, Detail = "Config file is empty." });
        }
        else
        {
            ScanUnicode(text, path, issues);

            try
            {
                using var doc = JsonDocument.Parse(text);
                ParseServers(doc.RootElement, path, issues);
            }
            catch (JsonException)
            {
                target.Status = "parse-error";
                issues.Add(new AuditIssue
                {
                    Severity = SevInfo,
                    Rule = "parse-error",
                    Target = path,
                    Detail = "Config is not valid JSON; structured rules were skipped.",
                });
            }
        }

        target.Issues = issues.ToArray();
        return target;
    }

    private static void ParseServers(JsonElement root, string path, List<AuditIssue> issues)
    {
        if (root.ValueKind != JsonValueKind.Object) return;
        if (!root.TryGetProperty("mcpServers", out JsonElement servers) || servers.ValueKind != JsonValueKind.Object)
            return;

        bool anyWrite = false;
        bool anyExec = false;

        foreach (JsonProperty prop in servers.EnumerateObject())
        {
            Caps caps = AuditServer(prop.Name, prop.Value, path, issues);
            if ((caps & Caps.Write) != 0) anyWrite = true;
            if ((caps & Caps.Exec) != 0) anyExec = true;
        }

        if (anyWrite && anyExec)
        {
            issues.Add(new AuditIssue
            {
                Severity = SevCritical,
                Rule = "toxic-pair",
                Target = path,
                Detail = "Config combines file-write capable and command-execution capable servers (toxic pair).",
            });
        }
    }

    private static Caps AuditServer(string name, JsonElement server, string path, List<AuditIssue> issues)
    {
        if (server.ValueKind != JsonValueKind.Object) return Caps.None;

        string command = server.TryGetProperty("command", out JsonElement c) && c.ValueKind == JsonValueKind.String
            ? c.GetString() ?? string.Empty
            : string.Empty;

        var args = new List<string>(4);
        if (server.TryGetProperty("args", out JsonElement a) && a.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in a.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String)
                    args.Add(item.GetString() ?? string.Empty);
        }

        string combined = BuildCommandLine(command, args);

        // 1. Unpinned execution
        CheckUnpinned(name, combined, path, issues);

        // 2. Toxic pair (per-server)
        bool write = HasWriteMarker(combined);
        bool exec = HasExecMarker(combined);
        if (write && exec)
        {
            issues.Add(new AuditIssue
            {
                Severity = SevCritical,
                Rule = "toxic-pair",
                Target = name,
                Detail = "Server exposes both file-write and command-execution capabilities in a single server.",
            });
        }

        // 3. Secret leakage (env blocks)
        if (server.TryGetProperty("env", out JsonElement env) && env.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty e in env.EnumerateObject())
                CheckSecret(name, e.Name, e.Value, path, issues);
        }

        // 5. Over-privileged paths
        CheckOverPrivilegedPaths(name, args, path, issues);

        Caps result = Caps.None;
        if (write) result |= Caps.Write;
        if (exec) result |= Caps.Exec;
        return result;
    }

    private static string BuildCommandLine(string command, List<string> args)
        => args.Count == 0 ? command : command + " " + string.Join(" ", args);

    private static void CheckUnpinned(string name, string combined, string path, List<AuditIssue> issues)
    {
        bool npx = combined.IndexOf("npx", StringComparison.OrdinalIgnoreCase) >= 0;
        bool uvx = combined.IndexOf("uvx", StringComparison.OrdinalIgnoreCase) >= 0;
        if (!npx && !uvx) return;

        bool autoInstall = combined.IndexOf("-y", StringComparison.Ordinal) >= 0
                        || combined.IndexOf("--yes", StringComparison.Ordinal) >= 0;

        bool pinned = ContainsVersionPin(combined);
        string runner = npx ? "npx" : "uvx";

        if (!pinned)
        {
            issues.Add(new AuditIssue
            {
                Severity = SevHigh,
                Rule = "unpinned-execution",
                Target = name,
                Detail = autoInstall
                    ? $"Unpinned {runner} auto-install ('-y') without an exact version pin."
                    : $"Unpinned {runner} invocation without an exact version pin.",
            });
        }
        else if (autoInstall)
        {
            issues.Add(new AuditIssue
            {
                Severity = SevLow,
                Rule = "unpinned-execution",
                Target = name,
                Detail = $"{runner} uses '-y' auto-install; verify the pinned version is trusted.",
            });
        }
    }

    private static bool ContainsVersionPin(string s)
    {
        ReadOnlySpan<char> span = s.AsSpan();
        for (int i = 0; i < span.Length; i++)
        {
            if (span[i] == '@' && i + 1 < span.Length && char.IsAsciiDigit(span[i + 1]))
            {
                int j = i + 1;
                while (j < span.Length && (char.IsAsciiDigit(span[j]) || span[j] == '.'))
                    j++;
                if (j > i + 1)
                    return true;
            }
        }
        return false;
    }

    private static bool HasWriteMarker(string combined)
        => ContainsAnySubstring(combined, WriteMarkers);

    private static bool HasExecMarker(string combined)
        => ContainsAnyWord(combined, ExecMarkers);

    private static bool ContainsAnySubstring(ReadOnlySpan<char> s, string[] markers)
    {
        foreach (string m in markers)
            if (s.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        return false;
    }

    private static bool ContainsAnyWord(ReadOnlySpan<char> s, string[] markers)
    {
        foreach (string m in markers)
            if (ContainsWord(s, m))
                return true;
        return false;
    }

    private static bool ContainsWord(ReadOnlySpan<char> s, ReadOnlySpan<char> token)
    {
        int idx = s.IndexOf(token, StringComparison.OrdinalIgnoreCase);
        while (idx >= 0)
        {
            bool beforeOk = idx == 0 || !IsWordChar(s[idx - 1]);
            int end = idx + token.Length;
            bool afterOk = end >= s.Length || !IsWordChar(s[end]);
            if (beforeOk && afterOk)
                return true;

            int next = s.Slice(end).IndexOf(token, StringComparison.OrdinalIgnoreCase);
            if (next < 0)
                return false;
            idx = end + next;
        }
        return false;
    }

    private static bool IsWordChar(char c)
        => char.IsAsciiLetterOrDigit(c) || c == '_';

    private static void CheckSecret(string server, string envKey, JsonElement value, string path, List<AuditIssue> issues)
    {
        string v = value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            _ => value.GetRawText(),
        };

        bool suspiciousName = ContainsAnySubstring(envKey, SecretKeyNames);
        bool suspiciousValue = HasSecretPattern(v);

        if (suspiciousName || suspiciousValue)
        {
            issues.Add(new AuditIssue
            {
                Severity = SevCritical,
                Rule = "secret-leakage",
                Target = $"{server}.env.{envKey}",
                Detail = $"Hardcoded secret detected in env block (key '{envKey}', value length {v.Length}).",
            });
        }
    }

    private static bool HasSecretPattern(string value)
    {
        if (string.IsNullOrEmpty(value)) return false;

        ReadOnlySpan<char> v = value.AsSpan();

        foreach (string p in SecretPrefixes)
            if (v.StartsWith(p, StringComparison.Ordinal))
                return true;

        // High-entropy heuristic: long mixed-case alphanumeric token.
        if (v.Length >= 24)
        {
            int upper = 0, lower = 0, digit = 0;
            foreach (char ch in v)
            {
                if (char.IsAsciiLetterUpper(ch)) upper++;
                else if (char.IsAsciiLetterLower(ch)) lower++;
                else if (char.IsAsciiDigit(ch)) digit++;
            }
            if (upper > 0 && lower > 0 && digit >= 3)
                return true;
        }

        return false;
    }

    private static void ScanUnicode(string text, string path, List<AuditIssue> issues)
    {
        ReadOnlySpan<char> span = text.AsSpan();
        for (int i = 0; i < span.Length; i++)
        {
            int cp = span[i];

            // Literal astral code point (UTF-16 surrogate pair), e.g. a real tag char.
            if (char.IsHighSurrogate(span[i]) && i + 1 < span.Length && char.IsLowSurrogate(span[i + 1]))
            {
                cp = char.ConvertToUtf32(span[i], span[i + 1]);
                i++;
            }
            // JSON escape "\uXXXX" (and surrogate-pair escapes for astral code points).
            else if (span[i] == '\\' && i + 5 < span.Length && span[i + 1] == 'u')
            {
                int hi = ParseHex4(span.Slice(i + 2, 4));
                if (hi >= 0)
                {
                    if (char.IsHighSurrogate((char)hi) && i + 11 < span.Length && span[i + 6] == '\\' && span[i + 7] == 'u')
                    {
                        int lo = ParseHex4(span.Slice(i + 8, 4));
                        if (lo >= 0 && char.IsLowSurrogate((char)lo))
                        {
                            cp = char.ConvertToUtf32((char)hi, (char)lo);
                            i += 11;
                        }
                    }
                    else if (!char.IsHighSurrogate((char)hi))
                    {
                        cp = hi;
                        i += 5;
                    }
                }
            }

            if (IsStealthCodePoint(cp))
            {
                issues.Add(new AuditIssue
                {
                    Severity = SevCritical,
                    Rule = "unicode-injection",
                    Target = path,
                    Detail = $"Stealth/invisible Unicode code point U+{cp:X4} detected at offset {i}.",
                });
                return;
            }
        }
    }

    private static int ParseHex4(ReadOnlySpan<char> s)
    {
        if (s.Length < 4) return -1;
        int v = 0;
        for (int i = 0; i < 4; i++)
        {
            char c = s[i];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return -1;
            v = (v << 4) | d;
        }
        return v;
    }

    private static bool IsStealthCodePoint(int cp)
    {
        if (cp >= 0xE0000 && cp <= 0xE007F) return true; // Unicode tag characters
        if (cp >= 0x202A && cp <= 0x202E) return true;   // bidi control characters
        if (cp >= 0x2066 && cp <= 0x2069) return true;   // bidi isolate characters

        switch (cp)
        {
            case 0x200B: // zero width space
            case 0x200C: // zero width non-joiner
            case 0x200D: // zero width joiner
            case 0x2060: // word joiner
            case 0xFEFF: // zero width no-break space / BOM
            case 0x00AD: // soft hyphen
            case 0x061C: // Arabic letter mark
            case 0x2028: // line separator
            case 0x2029: // paragraph separator
                return true;
        }
        return false;
    }

    private static void CheckOverPrivilegedPaths(string server, List<string> args, string path, List<AuditIssue> issues)
    {
        string? home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string? root = Environment.SystemDirectory.Length > 0 ? Path.GetPathRoot(Environment.SystemDirectory) : null;

        foreach (string raw in args)
        {
            string arg = raw.Trim();
            if (arg.Length == 0) continue;

            if (IsRootPath(arg, home, root))
            {
                issues.Add(new AuditIssue
                {
                    Severity = SevMedium,
                    Rule = "over-privileged-path",
                    Target = $"{server}.args",
                    Detail = $"Server argument exposes an over-privileged filesystem path: '{arg}'.",
                });
            }
        }
    }

    private static bool IsRootPath(string p, string? home, string? root)
    {
        ReadOnlySpan<char> s = p.AsSpan().Trim();
        if (s.Length == 0) return false;

        // Unix-style root
        if (s.Length == 1 && s[0] == '/') return true;

        // Windows drive root: "C:", "C:\", "C:/"
        if (s.Length >= 2 && char.IsAsciiLetter(s[0]) && s[1] == ':')
        {
            if (s.Length == 2) return true;
            if (s.Length == 3 && (s[2] == '\\' || s[2] == '/')) return true;
        }

        // Home directory roots
        if (s.Length == 1 && s[0] == '~') return true;
        if (s.StartsWith("~/", StringComparison.Ordinal) || s.StartsWith("~\\", StringComparison.Ordinal)) return true;
        if (!string.IsNullOrEmpty(home) && s.Equals(home, StringComparison.OrdinalIgnoreCase)) return true;

        // System root (e.g. "C:\" on Windows)
        if (!string.IsNullOrEmpty(root) && s.Equals(root, StringComparison.OrdinalIgnoreCase)) return true;

        return false;
    }

    private static void AddToSummary(AuditSummary summary, string severity)
    {
        switch (severity)
        {
            case SevCritical: summary.Critical++; break;
            case SevHigh: summary.High++; break;
            case SevMedium: summary.Medium++; break;
            case SevLow: summary.Low++; break;
            default: summary.Info++; break;
        }
    }

    private static int ComputeRiskScore(AuditSummary s)
    {
        int score = s.Critical * 25 + s.High * 10 + s.Medium * 4 + s.Low;
        return score > 100 ? 100 : score;
    }
}
