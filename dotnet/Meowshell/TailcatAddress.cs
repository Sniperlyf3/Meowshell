#nullable enable

namespace Meowshell;

/// <summary>
/// A tailcat address: opaque, base64-encoded, and always starting with
/// "tc". Wrapping it catches a stray empty string or a copy-paste mistake
/// at the API boundary, and reads better than a bare <c>string</c> at
/// every call site that specifically needs an address rather than any
/// text. Implicitly convertible to and from <c>string</c>, so existing
/// code passing a plain address string keeps working.
/// </summary>
public readonly record struct TailcatAddress
{
    private readonly string _value;

    /// <summary>Wraps <paramref name="value"/>, requiring it to start with "tc".</summary>
    /// <exception cref="FormatException"><paramref name="value"/> doesn't start with "tc".</exception>
    public TailcatAddress(string value)
    {
        if (!value.StartsWith("tc", StringComparison.Ordinal))
        {
            throw new FormatException($"\"{value}\" is not a tailcat address: it doesn't start with \"tc\".");
        }
        _value = value;
    }

    /// <summary>The address itself.</summary>
    public override string ToString() => _value;

    /// <summary>The address itself.</summary>
    public static implicit operator string(TailcatAddress address) => address._value;

    /// <summary>Wraps <paramref name="value"/>, requiring it to start with "tc".</summary>
    public static implicit operator TailcatAddress(string value) => new(value);
}
