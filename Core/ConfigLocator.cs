using System;
using System.Collections.Generic;
using System.IO;

namespace MCPGuard.Core;

/// <summary>
/// Auto-discovers MCP configuration files for Claude Desktop, Cursor, VS Code
/// and custom harnesses. Returns candidate paths; callers filter by existence.
/// </summary>
public static class ConfigLocator
{
    public static string[] GetDefaultPaths()
    {
        var list = new List<string>(8);

        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // Claude Desktop (Windows)
        if (appData.Length > 0)
            list.Add(Path.Combine(appData, "Claude", "claude_desktop_config.json"));

        if (userProfile.Length > 0)
        {
            // Claude Desktop (Linux / macOS style)
            list.Add(Path.Combine(userProfile, ".config", "Claude", "claude_desktop_config.json"));
            list.Add(Path.Combine(userProfile, "Library", "Application Support", "Claude", "claude_desktop_config.json"));

            // Cursor
            list.Add(Path.Combine(userProfile, ".cursor", "mcp.json"));

            // VS Code (user-level)
            list.Add(Path.Combine(userProfile, ".vscode", "mcp.json"));
        }

        if (appData.Length > 0)
        {
            // VS Code (Windows)
            list.Add(Path.Combine(appData, "Code", "User", "mcp.json"));
            // Cursor (Windows)
            list.Add(Path.Combine(appData, "Cursor", "User", "mcp.json"));
        }

        // Custom harness override (semicolon-separated list)
        string? custom = Environment.GetEnvironmentVariable("MCP_GUARD_CONFIG");
        if (!string.IsNullOrEmpty(custom))
            foreach (string p in custom.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                list.Add(p);

        return list.ToArray();
    }
}
