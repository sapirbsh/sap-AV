using System.Xml;
using System.Xml.Linq;

namespace SapAV.Core.Persistence;

/// <summary>One action of a scheduled task: an Exec (program + arguments) or a COM handler (CLSID + data).</summary>
public sealed record TaskAction(string? Command, string? Arguments, string? WorkingDirectory, Guid? ComClassId, string? ComData)
{
    public bool IsComHandler => ComClassId is not null;
}

/// <summary>What a task definition says (ROADMAP C2): enabled or not, who it runs as, and its actions.</summary>
/// <param name="UserId">The first principal's UserId as written (a SID, an account name or a group); null if none.</param>
public sealed record TaskDefinitionInfo(bool Enabled, string? UserId, IReadOnlyList<TaskAction> Actions);

/// <summary>
/// A hardened reader of task definition XML (the files under <c>System32\Tasks</c>). DTDs are refused outright (no
/// entity expansion, no external entities, no XXE), no resolver is set (nothing is fetched), the document is capped at
/// <see cref="MaxCharacters"/>, and at most <see cref="MaxActions"/> actions are read. Elements are matched by local name
/// so a missing or odd namespace still parses. Never throws: malformed input returns null with a reason.
/// </summary>
public static class TaskXml
{
    public const int MaxBytes = 1024 * 1024;
    public const long MaxCharacters = 1024 * 1024;
    public const int MaxActions = 32;
    public const int MaxFieldLength = 32767;

    public static TaskDefinitionInfo? Parse(byte[] data, out string? error)
    {
        ArgumentNullException.ThrowIfNull(data);
        error = null;
        if (data.Length > MaxBytes)
        {
            error = "The task file is larger than the size cap.";
            return null;
        }

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxCharacters,
            MaxCharactersFromEntities = 0,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            CloseInput = true,
        };

        try
        {
            using var reader = XmlReader.Create(new MemoryStream(data, writable: false), settings);
            var document = XDocument.Load(reader, LoadOptions.None);
            var info = Read(document.Root);
            error = info is null ? "Not a task definition (the root element isn't Task)." : null;
            return info;
        }
        catch (XmlException ex) when (ex.Message.Contains("DTD", StringComparison.OrdinalIgnoreCase))
        {
            error = "The task file has a DTD, which is refused.";
        }
        catch (XmlException)
        {
            error = "The task file isn't well-formed XML.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or IOException or FormatException)
        {
            error = "The task file can't be read.";
        }

        return null;
    }

    private static TaskDefinitionInfo? Read(XElement? root)
    {
        if (root is null || root.Name.LocalName != "Task")
        {
            return null;
        }

        var enabledText = Child(Child(root, "Settings"), "Enabled")?.Value.Trim();
        bool enabled = !string.Equals(enabledText, "false", StringComparison.OrdinalIgnoreCase) && enabledText != "0";
        string? userId = Text(Child(Children(Child(root, "Principals"), "Principal").FirstOrDefault(), "UserId"));
        var actions = new List<TaskAction>();
        foreach (var action in Child(root, "Actions")?.Elements() ?? [])
        {
            if (actions.Count >= MaxActions)
            {
                break;
            }

            if (action.Name.LocalName == "Exec")
            {
                actions.Add(new TaskAction(Text(Child(action, "Command")), Text(Child(action, "Arguments")),
                    Text(Child(action, "WorkingDirectory")), null, null));
            }
            else if (action.Name.LocalName == "ComHandler")
            {
                var clsid = Guid.TryParse(Text(Child(action, "ClassId")), out var id) ? id : Guid.Empty;
                actions.Add(new TaskAction(null, null, null, clsid, Text(Child(action, "Data"))));
            }
        }

        return new TaskDefinitionInfo(enabled, userId, actions);
    }

    private static XElement? Child(XElement? parent, string name) => Children(parent, name).FirstOrDefault();

    private static IEnumerable<XElement> Children(XElement? parent, string name) =>
        parent?.Elements().Where(e => e.Name.LocalName == name) ?? [];

    private static string? Text(XElement? element) => element?.Value is { } value
        ? value.Length > MaxFieldLength ? value[..MaxFieldLength] : value
        : null;
}
