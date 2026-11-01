using System.Text;
using System.Xml;

namespace SapAV.Core.Persistence;

/// <summary>One action of a scheduled task: an Exec (program + arguments) or a COM handler (CLSID + data).</summary>
public sealed record TaskAction(string? Command, string? Arguments, string? WorkingDirectory, Guid? ComClassId, string? ComData)
{
    public bool IsComHandler => ComClassId is not null;
}

/// <summary>What a task definition says (ROADMAP C2): enabled or not, who it runs as, and its actions.</summary>
/// <param name="UserId">The first principal's UserId as written (a SID, an account name or a group); null if none.</param>
/// <param name="Truncated">A cap cut something (more than <see cref="TaskXml.MaxActions"/> actions, or too much text): what follows wasn't read.</param>
public sealed record TaskDefinitionInfo(bool Enabled, string? UserId, IReadOnlyList<TaskAction> Actions, bool Truncated = false);

/// <summary>
/// A hardened <b>streaming</b> reader of task definition XML (the files under <c>System32\Tasks</c>), run only in the
/// sandboxed scan worker (section C review H2: a standard user can create files there). DTDs are refused outright (no entity
/// expansion, no external entities, no XXE), no resolver is set (nothing is fetched), the document is capped at
/// <see cref="MaxCharacters"/>, nesting at <see cref="MaxDepth"/> (no tree is built, and nothing here recurses, so depth
/// can't overflow a stack), and at most <see cref="MaxActions"/> actions and <see cref="MaxTotalCharacters"/> of text are
/// kept. Elements are matched by local name so a missing or odd namespace still parses. Never throws: malformed input
/// returns null with a reason.
/// </summary>
public static class TaskXml
{
    public const int MaxBytes = 1024 * 1024;
    public const long MaxCharacters = 1024 * 1024;
    public const int MaxActions = 32;
    public const int MaxFieldLength = 32767;

    /// <summary>Deepest element nesting accepted; a real task definition is 5 levels deep.</summary>
    public const int MaxDepth = 16;

    /// <summary>Most text kept over all fields, so the result fits the worker protocol's response cap whatever the characters.</summary>
    public const int MaxTotalCharacters = 32_000;

    private enum Field
    {
        None,
        Command,
        Arguments,
        WorkingDirectory,
        ClassId,
        Data,
    }

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
            return new Walk(reader).Run(out error);
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

    /// <summary>One pass over the document: only the first Settings / Principals / Actions (and first Principal) count.</summary>
    private sealed class Walk(XmlReader reader)
    {
        private readonly List<TaskAction> _actions = [];
        private readonly string[] _path = new string[MaxDepth + 1];
        private readonly Dictionary<Field, StringBuilder> _action = [];
        private readonly HashSet<string> _seenTop = [];
        private readonly StringBuilder _enabled = new();
        private readonly StringBuilder _userId = new();
        private bool _isCom;
        private bool _inAction;
        private bool _firstPrincipal = true;
        private bool _inPrincipal;
        private bool _enabledSeen;
        private bool _userIdSeen;
        private bool _inFirstTop;
        private StringBuilder? _text;
        private int _textDepth;
        private int _charactersLeft = MaxTotalCharacters;
        private bool _truncated;

        public TaskDefinitionInfo? Run(out string? error)
        {
            error = null;
            bool root = false;
            while (reader.Read())
            {
                switch (reader.NodeType)
                {
                    case XmlNodeType.Element:
                        if (reader.Depth >= MaxDepth)
                        {
                            error = $"The task file is nested deeper than {MaxDepth} levels.";
                            return null;
                        }

                        if (reader.Depth == 0)
                        {
                            root = true;
                            if (reader.LocalName != "Task")
                            {
                                error = "Not a task definition (the root element isn't Task).";
                                return null;
                            }
                        }

                        bool empty = reader.IsEmptyElement;
                        int depth = reader.Depth;
                        Open(depth, reader.LocalName);
                        if (empty)
                        {
                            Close(depth);
                        }

                        break;

                    case XmlNodeType.EndElement:
                        Close(reader.Depth);
                        break;

                    case XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace:
                        AddText(reader.Value);
                        break;
                }
            }

            if (!root)
            {
                error = "Not a task definition (the root element isn't Task).";
                return null;
            }

            string enabled = _enabled.ToString().Trim();
            return new TaskDefinitionInfo(
                !string.Equals(enabled, "false", StringComparison.OrdinalIgnoreCase) && enabled != "0",
                _userIdSeen ? _userId.ToString() : null, _actions, _truncated);
        }

        private void Open(int depth, string name)
        {
            _path[depth] = name;
            if (_text is not null)
            {
                return; // a field's text includes its descendants', as XElement.Value did
            }

            switch (depth)
            {
                case 1:
                    _inFirstTop = name is "Settings" or "Principals" or "Actions" && _seenTop.Add(name);
                    break;

                case 2 when _inFirstTop && _path[1] == "Settings" && name == "Enabled" && !_enabledSeen:
                    _enabledSeen = true;
                    Begin(_enabled, depth);
                    break;

                case 2 when _inFirstTop && _path[1] == "Principals" && name == "Principal":
                    _inPrincipal = _firstPrincipal;
                    _firstPrincipal = false;
                    break;

                case 2 when _inFirstTop && _path[1] == "Actions" && name is "Exec" or "ComHandler":
                    OpenAction(name);
                    break;

                case 3 when _inFirstTop && _path[1] == "Principals" && _path[2] == "Principal" && _inPrincipal && name == "UserId" && !_userIdSeen:
                    _userIdSeen = true;
                    Begin(_userId, depth);
                    break;

                case 3 when _inAction:
                    OpenActionField(depth, name);
                    break;
            }
        }

        private void OpenAction(string name)
        {
            if (_actions.Count >= MaxActions)
            {
                _truncated = true;
                return;
            }

            _inAction = true;
            _isCom = name == "ComHandler";
            _action.Clear();
        }

        private void OpenActionField(int depth, string name)
        {
            Field field = (_isCom, name) switch
            {
                (false, "Command") => Field.Command,
                (false, "Arguments") => Field.Arguments,
                (false, "WorkingDirectory") => Field.WorkingDirectory,
                (true, "ClassId") => Field.ClassId,
                (true, "Data") => Field.Data,
                _ => Field.None,
            };

            if (field != Field.None && !_action.ContainsKey(field))
            {
                _action[field] = new StringBuilder();
                Begin(_action[field], depth);
            }
        }

        private void Begin(StringBuilder text, int depth)
        {
            _text = text;
            _textDepth = depth;
        }

        private void AddText(string value)
        {
            if (_text is null)
            {
                return;
            }

            int room = Math.Max(Math.Min(MaxFieldLength - _text.Length, _charactersLeft), 0);
            int taken = Math.Min(value.Length, room);
            _truncated |= taken < value.Length;
            _text.Append(value, 0, taken);
            _charactersLeft -= taken;
        }

        private void Close(int depth)
        {
            if (_text is not null && depth == _textDepth)
            {
                _text = null;
            }

            if (_inAction && depth == 2)
            {
                _inAction = false;
                _actions.Add(_isCom
                    ? new TaskAction(null, null, null, Guid.TryParse(Text(Field.ClassId), out var id) ? id : Guid.Empty, Text(Field.Data))
                    : new TaskAction(Text(Field.Command), Text(Field.Arguments), Text(Field.WorkingDirectory), null, null));
            }
        }

        private string? Text(Field field) => _action.TryGetValue(field, out var text) ? text.ToString() : null;
    }
}
