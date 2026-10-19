using System.Text;

namespace SapAV.Core.Tests.TestSupport;

/// <summary>
/// The EICAR anti-virus test string, assembled at runtime. It is never stored whole in source or in the
/// compiled test assembly: the parts live in a runtime array (a constant <c>"a" + "b"</c> would be folded
/// into one literal by the compiler), so neither the repo nor the DLL trips a real AV scanner.
/// Tests should hash it from memory; never commit an EICAR file.
/// </summary>
internal static class Eicar
{
    /// <summary>Published SHA-256 of the 68-byte EICAR test file.</summary>
    public const string KnownSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private static readonly string[] Parts =
    [
        "X5O!P%@AP[4\\PZX",
        "54(P^)7CC)7}$",
        "EICAR-STANDARD-",
        "ANTIVIRUS-TEST-",
        "FILE!$H+H*",
    ];

    /// <summary>The 68 ASCII bytes of the EICAR test file.</summary>
    public static byte[] Bytes() => Encoding.ASCII.GetBytes(string.Concat(Parts));
}
