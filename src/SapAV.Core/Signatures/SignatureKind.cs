using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Signatures;

/// <summary>Where the signature that decided the result lives. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<SignatureKind>))]
public enum SignatureKind
{
    /// <summary>No signature was found (NotSigned), or the file was not checked.</summary>
    None,

    /// <summary>A signature inside the file (PE certificate table, script signature block, ...).</summary>
    Embedded,

    /// <summary>The file's hash is listed in a signed Windows catalog (<c>.cat</c>) under CatRoot.</summary>
    Catalog,
}
