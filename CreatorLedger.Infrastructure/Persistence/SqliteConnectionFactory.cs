using Microsoft.Data.Sqlite;

namespace CreatorLedger.Infrastructure.Persistence;

/// <summary>
/// Factory for creating properly configured SQLite connections.
/// Applies WAL mode, busy timeout, and other settings.
/// </summary>
public sealed class SqliteConnectionFactory : IDisposable
{
    private readonly string _connectionString;
    private bool _initialized;
    private readonly object _initLock = new();

    public SqliteConnectionFactory(string databasePath)
    {
        // Build connection string with recommended settings
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            // Foreign keys enforcement
            ForeignKeys = true
        };

        _connectionString = builder.ConnectionString;
    }

    /// <summary>
    /// Gets the connection string for use with the migrator.
    /// </summary>
    public string ConnectionString => _connectionString;

    /// <summary>
    /// Creates a new open connection with proper PRAGMA settings.
    /// Caller is responsible for disposing.
    /// </summary>
    public SqliteConnection CreateConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();

        // Apply PRAGMAs on each connection
        ApplyPragmas(connection);

        // One-time database initialization
        EnsureInitialized(connection);

        return connection;
    }

    private static void ApplyPragmas(SqliteConnection connection)
    {
        using var cmd = connection.CreateCommand();

        // WAL mode for better concurrency and crash safety
        cmd.CommandText = "PRAGMA journal_mode = WAL";
        cmd.ExecuteNonQuery();

        // Synchronous NORMAL: good balance of safety and performance
        // Use FULL for maximum durability (slower)
        cmd.CommandText = "PRAGMA synchronous = NORMAL";
        cmd.ExecuteNonQuery();

        // Busy timeout: wait up to 5 seconds for locks
        cmd.CommandText = "PRAGMA busy_timeout = 5000";
        cmd.ExecuteNonQuery();

        // Enable foreign key enforcement
        cmd.CommandText = "PRAGMA foreign_keys = ON";
        cmd.ExecuteNonQuery();

        // Optimize for modern SSDs
        cmd.CommandText = "PRAGMA temp_store = MEMORY";
        cmd.ExecuteNonQuery();

        // Memory-mapped I/O for better read performance (64MB)
        cmd.CommandText = "PRAGMA mmap_size = 67108864";
        cmd.ExecuteNonQuery();
    }

    private void EnsureInitialized(SqliteConnection connection)
    {
        if (_initialized)
            return;

        lock (_initLock)
        {
            if (_initialized)
                return;

            // Run migrations
            var migrator = new Migrations.SqliteMigrator(_connectionString);
            migrator.MigrateToLatest();

            _initialized = true;
        }
    }

    public void Dispose()
    {
        // Nothing to dispose - connections are created on demand
    }
}
