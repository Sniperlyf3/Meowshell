#nullable enable

namespace Meowshell;

/// <summary>A tailcat address: opaque, base64-encoded, and always starting with "tc". Implicitly convertible to and from <c>string</c>.</summary>
public readonly record struct TailcatAddress
{
    private readonly string _value;

    /// <summary>Wraps <paramref name="value"/>, requiring the same <c>tc&lt;base64url&gt;</c> shape the native client recognizes.</summary>
    /// <exception cref="FormatException"><paramref name="value"/> is not syntactically a tailcat address.</exception>
    public TailcatAddress(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.StartsWith("tc", StringComparison.Ordinal) || value.Length == 2)
            throw new FormatException($"\"{value}\" is not a tailcat address.");

        var encoded = value[2..];
        if (encoded.Any(ch => !(char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_')) || encoded.Length % 4 == 1)
            throw new FormatException($"\"{value}\" is not a valid base64url tailcat address.");

        // Validate the raw, unpadded base64url payload rather than only its
        // alphabet so malformed lengths/encodings fail at the API boundary.
        var padded = encoded.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        try
        {
            _ = Convert.FromBase64String(padded);
        }
        catch (FormatException ex)
        {
            throw new FormatException($"\"{value}\" is not a valid base64url tailcat address.", ex);
        }
        _value = value;
    }

    /// <summary>The address itself.</summary>
    public override string ToString() =>
        _value ?? throw new InvalidOperationException("an uninitialized TailcatAddress has no value");

    /// <summary>The address itself.</summary>
    public static implicit operator string(TailcatAddress address) => address.ToString();

    /// <summary>Wraps <paramref name="value"/>, validating the tailcat address syntax.</summary>
    public static implicit operator TailcatAddress(string value) => new(value);
}
