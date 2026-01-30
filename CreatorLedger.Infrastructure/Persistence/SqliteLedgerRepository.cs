using System.Text.Json;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Ledger;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using Microsoft.Data.Sqlite;
using Shared.Crypto;

namespace CreatorLedger.Infrastructure.Persistence;

/// <summary>
/// SQLite implementation of the append-only ledger repository.
///
/// CRITICAL INVARIANTS:
/// - Events are ordered by seq, NOT by timestamp
/// - payload_json is stored as canonical JSON and never recomputed
/// - event_hash is computed once and stored
/// - PreviousEventHash must match the current tip at append time
/// </summary>
public sealed class SqliteLedgerRepository : ILedgerRepository
{
    private readonly SqliteConnectionFactory _connectionFactory;
    private readonly ICreatorIdentityRepository _identityRepository;

    // JSON serializer options matching CanonicalJson for consistency
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = null,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never
    };

    public SqliteLedgerRepository(
        SqliteConnectionFactory connectionFactory,
        ICreatorIdentityRepository identityRepository)
    {
        _connectionFactory = connectionFactory;
        _identityRepository = identityRepository;
    }

    public async Task AppendAsync(LedgerEvent ledgerEvent, CancellationToken cancellationToken = default)
    {
        using var connection = _connectionFactory.CreateConnection();

        // Use IMMEDIATE transaction to get write lock immediately
        // This prevents race conditions during tip check
        using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable);

        try
        {
            // 1. Read current tip (seq, event_hash)
            var (currentSeq, currentTipHash) = GetCurrentTip(connection, transaction);

            // 2. Verify event.PreviousEventHash matches tip
            if (ledgerEvent.PreviousEventHash != currentTipHash)
            {
                throw new InvalidOperationException(
                    $"Event chain broken: expected PreviousEventHash={currentTipHash}, got {ledgerEvent.PreviousEventHash}");
            }

            // 3. Build canonical payload JSON
            var (payloadJson, signature, creatorId, creatorPublicKey, assetId) =
                await BuildEventDataAsync(ledgerEvent, cancellationToken);

            // 4. Compute event hash using frozen LedgerEventSignable contract
            var nextSeq = currentSeq + 1;
            var eventHash = EventHasher.ComputeHash(
                ledgerEvent.Id.ToString(),
                nextSeq,
                ledgerEvent.EventType,
                ledgerEvent.OccurredAtUtc,
                ledgerEvent.PreviousEventHash,
                payloadJson,
                signature,
                creatorPublicKey);

            // 5. Insert event

            using var cmd = connection.CreateCommand();
            cmd.Transaction = transaction;
            cmd.CommandText = """
                INSERT INTO ledger_events (
                    id, seq, event_type, occurred_at_utc, previous_event_hash,
                    event_hash, asset_id, payload_json, signature_base64,
                    creator_id, creator_public_key, schema_version
                )
                VALUES (
                    @id, @seq, @eventType, @occurredAt, @prevHash,
                    @eventHash, @assetId, @payloadJson, @signature,
                    @creatorId, @creatorPublicKey, @schemaVersion
                )
                """;

            cmd.Parameters.AddWithValue("@id", ledgerEvent.Id.ToString());
            cmd.Parameters.AddWithValue("@seq", nextSeq);
            cmd.Parameters.AddWithValue("@eventType", ledgerEvent.EventType);
            cmd.Parameters.AddWithValue("@occurredAt", ledgerEvent.OccurredAtUtc.ToString("O"));
            cmd.Parameters.AddWithValue("@prevHash", ledgerEvent.PreviousEventHash.ToString());
            cmd.Parameters.AddWithValue("@eventHash", eventHash.ToString());
            cmd.Parameters.AddWithValue("@assetId", assetId ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@payloadJson", payloadJson);
            cmd.Parameters.AddWithValue("@signature", signature ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@creatorId", creatorId ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@creatorPublicKey", creatorPublicKey ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@schemaVersion", EventPayloads.SchemaVersion);

            cmd.ExecuteNonQuery();

            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }

    public Task<IReadOnlyList<LedgerEvent>> GetEventsForAssetAsync(
        AssetId assetId,
        CancellationToken cancellationToken = default)
    {
        using var connection = _connectionFactory.CreateConnection();
        using var cmd = connection.CreateCommand();

        // Order by seq, NOT by occurred_at_utc
        cmd.CommandText = """
            SELECT id, seq, event_type, occurred_at_utc, previous_event_hash,
                   event_hash, asset_id, payload_json, signature_base64,
                   creator_id, creator_public_key, schema_version
            FROM ledger_events
            WHERE asset_id = @assetId
            ORDER BY seq ASC
            """;

        cmd.Parameters.AddWithValue("@assetId", assetId.ToString());

        var events = new List<LedgerEvent>();
        using var reader = cmd.ExecuteReader();

        while (reader.Read())
        {
            var evt = ReadEvent(reader);
            if (evt != null)
                events.Add(evt);
        }

        return Task.FromResult<IReadOnlyList<LedgerEvent>>(events);
    }

    public Task<Digest256> GetLedgerTipAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _connectionFactory.CreateConnection();
        var (_, tipHash) = GetCurrentTip(connection, null);
        return Task.FromResult(tipHash);
    }

    public Task<LedgerEvent?> GetEventByIdAsync(EventId eventId, CancellationToken cancellationToken = default)
    {
        using var connection = _connectionFactory.CreateConnection();
        using var cmd = connection.CreateCommand();

        cmd.CommandText = """
            SELECT id, seq, event_type, occurred_at_utc, previous_event_hash,
                   event_hash, asset_id, payload_json, signature_base64,
                   creator_id, creator_public_key, schema_version
            FROM ledger_events
            WHERE id = @id
            """;

        cmd.Parameters.AddWithValue("@id", eventId.ToString());

        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
            return Task.FromResult<LedgerEvent?>(null);

        var evt = ReadEvent(reader);
        return Task.FromResult(evt);
    }

    public Task<long> GetEventCountAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _connectionFactory.CreateConnection();
        using var cmd = connection.CreateCommand();

        cmd.CommandText = "SELECT COUNT(*) FROM ledger_events";
        var count = Convert.ToInt64(cmd.ExecuteScalar());

        return Task.FromResult(count);
    }

    #region Private Helpers

    private static (long seq, Digest256 hash) GetCurrentTip(SqliteConnection connection, SqliteTransaction? transaction)
    {
        using var cmd = connection.CreateCommand();
        cmd.Transaction = transaction;
        cmd.CommandText = """
            SELECT seq, event_hash
            FROM ledger_events
            ORDER BY seq DESC
            LIMIT 1
            """;

        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
        {
            // Empty ledger - genesis state
            return (0, Digest256.Zero);
        }

        var seq = reader.GetInt64(0);
        var hash = Digest256.Parse(reader.GetString(1));
        return (seq, hash);
    }

    private async Task<(string payloadJson, string? signature, string? creatorId, string? creatorPublicKey, string? assetId)>
        BuildEventDataAsync(LedgerEvent evt, CancellationToken cancellationToken)
    {
        return evt switch
        {
            AssetAttestedEvent e => await BuildAssetAttestedDataAsync(e, cancellationToken),
            AssetDerivedEvent e => await BuildAssetDerivedDataAsync(e, cancellationToken),
            CreatorCreatedEvent e => BuildCreatorCreatedData(e),
            LedgerAnchoredEvent e => BuildLedgerAnchoredData(e),
            AssetExportedEvent e => BuildAssetExportedData(e),
            _ => throw new NotSupportedException($"Unknown event type: {evt.GetType().Name}")
        };
    }

    private async Task<(string, string?, string?, string?, string?)> BuildAssetAttestedDataAsync(
        AssetAttestedEvent e, CancellationToken ct)
    {
        // Look up creator's public key
        var identity = await _identityRepository.GetAsync(e.CreatorId, ct);
        var publicKey = identity?.PublicKey.ToString() ?? "";

        var payload = new EventPayloads.AssetAttestedPayload
        {
            AttestationId = e.AttestationId.ToString(),
            AssetId = e.AssetId.ToString(),
            ContentHash = e.ContentHash.ToString(),
            CreatorId = e.CreatorId.ToString(),
            CreatorPublicKey = $"ed25519:{publicKey}"
        };

        var json = JsonSerializer.Serialize(payload, JsonOptions);
        return (json, e.Signature.ToString(), e.CreatorId.ToString(), $"ed25519:{publicKey}", e.AssetId.ToString());
    }

    private async Task<(string, string?, string?, string?, string?)> BuildAssetDerivedDataAsync(
        AssetDerivedEvent e, CancellationToken ct)
    {
        var identity = await _identityRepository.GetAsync(e.CreatorId, ct);
        var publicKey = identity?.PublicKey.ToString() ?? "";

        var payload = new EventPayloads.AssetDerivedPayload
        {
            AttestationId = e.AttestationId.ToString(),
            AssetId = e.AssetId.ToString(),
            ContentHash = e.ContentHash.ToString(),
            CreatorId = e.CreatorId.ToString(),
            CreatorPublicKey = $"ed25519:{publicKey}",
            ParentAssetId = e.ParentAssetId.ToString(),
            ParentAttestationId = e.ParentAttestationId?.ToString()
        };

        var json = JsonSerializer.Serialize(payload, JsonOptions);
        return (json, e.Signature.ToString(), e.CreatorId.ToString(), $"ed25519:{publicKey}", e.AssetId.ToString());
    }

    private static (string, string?, string?, string?, string?) BuildCreatorCreatedData(CreatorCreatedEvent e)
    {
        var payload = new EventPayloads.CreatorCreatedPayload
        {
            CreatorId = e.CreatorId.ToString(),
            PublicKey = $"ed25519:{e.PublicKey}",
            DisplayName = e.DisplayName
        };

        var json = JsonSerializer.Serialize(payload, JsonOptions);
        // CreatorCreated events don't have a signature or asset_id
        return (json, null, e.CreatorId.ToString(), $"ed25519:{e.PublicKey}", null);
    }

    private static (string, string?, string?, string?, string?) BuildLedgerAnchoredData(LedgerAnchoredEvent e)
    {
        var payload = new EventPayloads.LedgerAnchoredPayload
        {
            LedgerRootHash = e.LedgerRootHash.ToString(),
            ChainName = e.ChainName,
            TransactionId = e.TransactionId,
            BlockNumber = e.BlockNumber
        };

        var json = JsonSerializer.Serialize(payload, JsonOptions);
        // Anchor events are system events - no creator, no asset
        return (json, null, null, null, null);
    }

    private static (string, string?, string?, string?, string?) BuildAssetExportedData(AssetExportedEvent e)
    {
        var payload = new EventPayloads.AssetExportedPayload
        {
            AssetId = e.AssetId.ToString(),
            AttestationId = e.AttestationId.ToString(),
            ExportTarget = e.ExportTarget
        };

        var json = JsonSerializer.Serialize(payload, JsonOptions);
        // Export events track asset but don't have a signature
        return (json, null, null, null, e.AssetId.ToString());
    }

    private static LedgerEvent? ReadEvent(SqliteDataReader reader)
    {
        var eventType = reader.GetString(2);
        var id = EventId.Parse(reader.GetString(0));
        var occurredAt = DateTimeOffset.Parse(reader.GetString(3));
        var previousHash = Digest256.Parse(reader.GetString(4));
        var payloadJson = reader.GetString(7);

        return eventType switch
        {
            AssetAttestedEvent.TypeName => ReadAssetAttestedEvent(id, occurredAt, previousHash, payloadJson, reader),
            AssetDerivedEvent.TypeName => ReadAssetDerivedEvent(id, occurredAt, previousHash, payloadJson, reader),
            CreatorCreatedEvent.TypeName => ReadCreatorCreatedEvent(id, occurredAt, previousHash, payloadJson),
            LedgerAnchoredEvent.TypeName => ReadLedgerAnchoredEvent(id, occurredAt, previousHash, payloadJson),
            AssetExportedEvent.TypeName => ReadAssetExportedEvent(id, occurredAt, previousHash, payloadJson),
            _ => null // Unknown event type - skip
        };
    }

    private static AssetAttestedEvent ReadAssetAttestedEvent(
        EventId id, DateTimeOffset occurredAt, Digest256 previousHash,
        string payloadJson, SqliteDataReader reader)
    {
        var payload = JsonSerializer.Deserialize<EventPayloads.AssetAttestedPayload>(payloadJson, JsonOptions)!;
        var signatureBase64 = reader.GetString(8);

        return new AssetAttestedEvent(
            id,
            occurredAt,
            previousHash,
            AttestationId.Parse(payload.AttestationId),
            AssetId.Parse(payload.AssetId),
            ContentHash.Parse(payload.ContentHash),
            CreatorId.Parse(payload.CreatorId),
            Ed25519Signature.Parse(signatureBase64));
    }

    private static AssetDerivedEvent ReadAssetDerivedEvent(
        EventId id, DateTimeOffset occurredAt, Digest256 previousHash,
        string payloadJson, SqliteDataReader reader)
    {
        var payload = JsonSerializer.Deserialize<EventPayloads.AssetDerivedPayload>(payloadJson, JsonOptions)!;
        var signatureBase64 = reader.GetString(8);

        return new AssetDerivedEvent(
            id,
            occurredAt,
            previousHash,
            AttestationId.Parse(payload.AttestationId),
            AssetId.Parse(payload.AssetId),
            ContentHash.Parse(payload.ContentHash),
            CreatorId.Parse(payload.CreatorId),
            Ed25519Signature.Parse(signatureBase64),
            AssetId.Parse(payload.ParentAssetId),
            payload.ParentAttestationId != null ? AttestationId.Parse(payload.ParentAttestationId) : null);
    }

    private static CreatorCreatedEvent ReadCreatorCreatedEvent(
        EventId id, DateTimeOffset occurredAt, Digest256 previousHash, string payloadJson)
    {
        var payload = JsonSerializer.Deserialize<EventPayloads.CreatorCreatedPayload>(payloadJson, JsonOptions)!;

        // Parse public key (strip "ed25519:" prefix)
        var publicKeyBase64 = payload.PublicKey.StartsWith("ed25519:")
            ? payload.PublicKey[8..]
            : payload.PublicKey;

        return new CreatorCreatedEvent(
            id,
            occurredAt,
            previousHash,
            CreatorId.Parse(payload.CreatorId),
            Ed25519PublicKey.Parse(publicKeyBase64),
            payload.DisplayName);
    }

    private static LedgerAnchoredEvent ReadLedgerAnchoredEvent(
        EventId id, DateTimeOffset occurredAt, Digest256 previousHash, string payloadJson)
    {
        var payload = JsonSerializer.Deserialize<EventPayloads.LedgerAnchoredPayload>(payloadJson, JsonOptions)!;

        return new LedgerAnchoredEvent(
            id,
            occurredAt,
            previousHash,
            Digest256.Parse(payload.LedgerRootHash),
            payload.ChainName,
            payload.TransactionId,
            payload.BlockNumber);
    }

    private static AssetExportedEvent ReadAssetExportedEvent(
        EventId id, DateTimeOffset occurredAt, Digest256 previousHash, string payloadJson)
    {
        var payload = JsonSerializer.Deserialize<EventPayloads.AssetExportedPayload>(payloadJson, JsonOptions)!;

        return new AssetExportedEvent(
            id,
            occurredAt,
            previousHash,
            AssetId.Parse(payload.AssetId),
            AttestationId.Parse(payload.AttestationId),
            payload.ExportTarget);
    }

    #endregion
}
