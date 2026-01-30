using CreatorLedger.Infrastructure.Migrations;
using Microsoft.Data.Sqlite;

namespace CreatorLedger.Tests.Integration;

public class SqliteMigrationTests : IDisposable
{
    private readonly string _tempDbPath;

    public SqliteMigrationTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"migration_test_{Guid.NewGuid():N}.db");
    }

    public void Dispose()
    {
        try
        {
            if (File.Exists(_tempDbPath))
                File.Delete(_tempDbPath);
        }
        catch { }
    }

    [Fact]
    public void MigrateToLatest_CreatesAllTables()
    {
        var connectionString = $"Data Source={_tempDbPath}";
        var migrator = new SqliteMigrator(connectionString);

        migrator.MigrateToLatest();

        // Verify tables exist
        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        Assert.True(TableExists(connection, "creators"));
        Assert.True(TableExists(connection, "ledger_events"));
        Assert.True(TableExists(connection, "schema_migrations"));
    }

    [Fact]
    public void MigrateToLatest_RecordsMigrationVersion()
    {
        var connectionString = $"Data Source={_tempDbPath}";
        var migrator = new SqliteMigrator(connectionString);

        migrator.MigrateToLatest();

        var version = migrator.GetCurrentVersion();
        Assert.True(version >= 1);
    }

    [Fact]
    public void MigrateToLatest_IsIdempotent()
    {
        var connectionString = $"Data Source={_tempDbPath}";
        var migrator = new SqliteMigrator(connectionString);

        // Run migrations twice
        migrator.MigrateToLatest();
        var versionAfterFirst = migrator.GetCurrentVersion();

        migrator.MigrateToLatest();
        var versionAfterSecond = migrator.GetCurrentVersion();

        Assert.Equal(versionAfterFirst, versionAfterSecond);
    }

    [Fact]
    public void LedgerEvents_HasAppendOnlyTriggers()
    {
        var connectionString = $"Data Source={_tempDbPath}";
        var migrator = new SqliteMigrator(connectionString);
        migrator.MigrateToLatest();

        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        // Insert a test event
        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = """
                INSERT INTO ledger_events (
                    id, seq, event_type, occurred_at_utc, previous_event_hash,
                    event_hash, payload_json, signature_base64, schema_version
                )
                VALUES (
                    'test-id', 1, 'test', '2024-01-01T00:00:00Z', 'abc',
                    'def', '{}', '', 'event.v1'
                )
                """;
            cmd.ExecuteNonQuery();
        }

        // Attempt UPDATE - should fail
        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "UPDATE ledger_events SET event_type = 'modified' WHERE id = 'test-id'";
            var ex = Assert.Throws<SqliteException>(() => cmd.ExecuteNonQuery());
            Assert.Contains("append-only", ex.Message);
        }

        // Attempt DELETE - should fail
        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "DELETE FROM ledger_events WHERE id = 'test-id'";
            var ex = Assert.Throws<SqliteException>(() => cmd.ExecuteNonQuery());
            Assert.Contains("append-only", ex.Message);
        }
    }

    private static bool TableExists(SqliteConnection connection, string tableName)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=@name";
        cmd.Parameters.AddWithValue("@name", tableName);
        return Convert.ToInt64(cmd.ExecuteScalar()) > 0;
    }
}
