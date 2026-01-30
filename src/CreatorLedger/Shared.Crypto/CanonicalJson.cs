using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Shared.Crypto;

/// <summary>
/// Deterministic JSON serialization for signing.
/// Produces canonical output that is stable across serialization round-trips.
///
/// GUARANTEES (do not modify without version bump):
/// - UTF-8 encoding, no BOM
/// - No whitespace (compact)
/// - No null property omission (nulls are explicit)
/// - Stable ASCII escaping (UnsafeRelaxedJsonEscaping)
/// - Invariant culture for all formatting
/// - Property order controlled by JsonPropertyOrder attributes
/// - GUIDs formatted as "D" format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
/// </summary>
public static class CanonicalJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        // UTF-8, no BOM (default for SerializeToUtf8Bytes)

        // No indentation - compact output, no whitespace
        WriteIndented = false,

        // Property names as-is (ordering via JsonPropertyOrder attributes)
        PropertyNamingPolicy = null,

        // Stable ASCII escaping - don't escape unnecessarily
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,

        // Include null values explicitly (no omission)
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,

        // Deterministic number formatting
        NumberHandling = JsonNumberHandling.Strict
    };

    /// <summary>
    /// Serializes an object to canonical JSON bytes (UTF-8, no BOM).
    /// This is THE signing input - nothing else.
    /// </summary>
    public static byte[] SerializeToBytes<T>(T value)
    {
        return JsonSerializer.SerializeToUtf8Bytes(value, Options);
    }

    /// <summary>
    /// Serializes an object to canonical JSON string.
    /// </summary>
    public static string Serialize<T>(T value)
    {
        return JsonSerializer.Serialize(value, Options);
    }

    /// <summary>
    /// Computes the Digest256 of the canonical JSON representation.
    /// </summary>
    public static Digest256 HashOf<T>(T value)
    {
        var bytes = SerializeToBytes(value);
        return Digest256.Compute(bytes);
    }

    /// <summary>
    /// Formats a DateTimeOffset in ISO 8601 format for canonical serialization.
    /// Uses the "O" format with UTC normalization.
    /// </summary>
    public static string FormatTimestamp(DateTimeOffset timestamp)
    {
        // Always store as UTC for determinism
        return timestamp.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Parses a canonical timestamp string back to DateTimeOffset.
    /// </summary>
    public static DateTimeOffset ParseTimestamp(string timestamp)
    {
        return DateTimeOffset.Parse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
    }

    /// <summary>
    /// Formats a GUID in canonical "D" format for signing.
    /// Always use this for GUIDs in signable payloads.
    /// </summary>
    public static string FormatGuid(Guid guid)
    {
        return guid.ToString("D", CultureInfo.InvariantCulture);
    }
}
