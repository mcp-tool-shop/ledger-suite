using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Primitives;
using Microsoft.Data.Sqlite;
using Shared.Crypto;

namespace CreatorLedger.Infrastructure.Persistence;

/// <summary>
/// SQLite implementation of the creator identity repository.
/// </summary>
public sealed class SqliteCreatorIdentityRepository : ICreatorIdentityRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;

    public SqliteCreatorIdentityRepository(SqliteConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public Task AddAsync(CreatorIdentity identity, CancellationToken cancellationToken = default)
    {
        using var connection = _connectionFactory.CreateConnection();
        using var cmd = connection.CreateCommand();

        cmd.CommandText = """
            INSERT INTO creators (id, public_key, display_name, created_at_utc)
            VALUES (@id, @publicKey, @displayName, @createdAt)
            """;

        cmd.Parameters.AddWithValue("@id", identity.Id.ToString());
        cmd.Parameters.AddWithValue("@publicKey", FormatPublicKey(identity.PublicKey));
        cmd.Parameters.AddWithValue("@displayName", identity.DisplayName ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@createdAt", identity.CreatedAtUtc.ToString("O"));

        cmd.ExecuteNonQuery();

        return Task.CompletedTask;
    }

    public Task<CreatorIdentity?> GetAsync(CreatorId id, CancellationToken cancellationToken = default)
    {
        using var connection = _connectionFactory.CreateConnection();
        using var cmd = connection.CreateCommand();

        cmd.CommandText = """
            SELECT id, public_key, display_name, created_at_utc
            FROM creators
            WHERE id = @id
            """;

        cmd.Parameters.AddWithValue("@id", id.ToString());

        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
            return Task.FromResult<CreatorIdentity?>(null);

        var identity = ReadIdentity(reader);
        return Task.FromResult<CreatorIdentity?>(identity);
    }

    /// <summary>
    /// Gets a creator identity by their public key.
    /// </summary>
    public Task<CreatorIdentity?> GetByPublicKeyAsync(Ed25519PublicKey publicKey, CancellationToken cancellationToken = default)
    {
        using var connection = _connectionFactory.CreateConnection();
        using var cmd = connection.CreateCommand();

        cmd.CommandText = """
            SELECT id, public_key, display_name, created_at_utc
            FROM creators
            WHERE public_key = @publicKey
            """;

        cmd.Parameters.AddWithValue("@publicKey", FormatPublicKey(publicKey));

        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
            return Task.FromResult<CreatorIdentity?>(null);

        var identity = ReadIdentity(reader);
        return Task.FromResult<CreatorIdentity?>(identity);
    }

    /// <summary>
    /// Checks if a creator with the given ID exists.
    /// </summary>
    public Task<bool> ExistsAsync(CreatorId id, CancellationToken cancellationToken = default)
    {
        using var connection = _connectionFactory.CreateConnection();
        using var cmd = connection.CreateCommand();

        cmd.CommandText = "SELECT COUNT(1) FROM creators WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", id.ToString());

        var count = Convert.ToInt64(cmd.ExecuteScalar());
        return Task.FromResult(count > 0);
    }

    private static CreatorIdentity ReadIdentity(SqliteDataReader reader)
    {
        var id = CreatorId.Parse(reader.GetString(0));
        var publicKey = ParsePublicKey(reader.GetString(1));
        var displayName = reader.IsDBNull(2) ? null : reader.GetString(2);
        var createdAt = DateTimeOffset.Parse(reader.GetString(3));

        return CreatorIdentity.Reconstitute(id, publicKey, displayName, createdAt);
    }

    /// <summary>
    /// Formats a public key for storage: "ed25519:{base64}"
    /// </summary>
    private static string FormatPublicKey(Ed25519PublicKey key)
    {
        return $"ed25519:{key}";
    }

    /// <summary>
    /// Parses a public key from storage format.
    /// </summary>
    private static Ed25519PublicKey ParsePublicKey(string stored)
    {
        const string prefix = "ed25519:";
        if (!stored.StartsWith(prefix, StringComparison.Ordinal))
            throw new FormatException($"Invalid public key format: expected 'ed25519:' prefix");

        var base64 = stored[prefix.Length..];
        return Ed25519PublicKey.Parse(base64);
    }
}
