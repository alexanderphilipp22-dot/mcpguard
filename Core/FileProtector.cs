using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace MCPGuard.Core;

/// <summary>
/// OS-level write protection for MCP config files.
/// Lock  = ReadOnly attribute + ACL deny-write rule for "Everyone".
/// Unlock = removes the ACL deny rule + clears the ReadOnly attribute.
/// The ACL portion is best-effort (falls back to ReadOnly on non-NTFS volumes).
/// </summary>
public static class FileProtector
{
    private static FileSystemAccessRule CreateDenyWriteRule()
        => new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.Write,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Deny);

    public static bool Lock(string path, out string message)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                message = $"not found: {path}";
                return false;
            }

            // Set ReadOnly first: the ACL deny below also blocks WriteAttributes.
            file.IsReadOnly = true;

            bool aclApplied = false;
            try
            {
                FileSecurity security = file.GetAccessControl();
                security.AddAccessRule(CreateDenyWriteRule());
                file.SetAccessControl(security);
                aclApplied = true;
            }
            catch (Exception)
            {
                // Non-NTFS or unsupported filesystem: fall back to ReadOnly only.
            }

            message = aclApplied
                ? $"locked (read-only + ACL deny-write): {path}"
                : $"locked (read-only): {path}";
            return true;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
        }
    }

    public static bool Unlock(string path, out string message)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                message = $"not found: {path}";
                return false;
            }

            try
            {
                FileSecurity security = file.GetAccessControl();
                security.RemoveAccessRule(CreateDenyWriteRule());
                file.SetAccessControl(security);
            }
            catch (Exception)
            {
                // Best effort: ReadOnly removal below still proceeds.
            }

            file.IsReadOnly = false;
            message = $"unlocked: {path}";
            return true;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
        }
    }
}
