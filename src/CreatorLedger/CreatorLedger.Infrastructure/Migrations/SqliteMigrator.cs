using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace CreatorLedger.Infrastructure.Migrations;

/// <summary>
/// Simple SQL migration runner for SQLite.
/// Reads numbered .sql files from embedded resources and applies them in order.
/// </summary>
public sealed class SqliteMigrator
{
    private readonly string _connectionString;

    public SqliteMigrator(string connectionString)
    {
        _connectionString = connectionString;
    }

    /// <summary>
    /// Runs all pending migrations.
    /// </summary>
    public void MigrateToLatest()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        // Ensure schema_migrations table exists (bootstrap)
        EnsureMigrationsTable(connection);

        // Get already-applied migrations
        var appliedVersions = GetAppliedVersions(connection);

        // Get all migration resources
        var migrations = GetMigrationResources();

        foreach (var (version, name, sql) in migrations.OrderBy(m => m.Version))
        {
            if (appliedVersions.Contains(version))
                continue;

            ApplyMigration(connection, version, name, sql);
        }
    }

    /// <summary>
    /// Gets the current schema version (highest applied migration).
    /// </summary>
    public int GetCurrentVersion()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        EnsureMigrationsTable(connection);

        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT MAX(version) FROM schema_migrations";
        var result = cmd.ExecuteScalar();
        return result == DBNull.Value ? 0 : Convert.ToInt32(result);
    }

    private static void EnsureMigrationsTable(SqliteConnection connection)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at_utc TEXT NOT NULL
            )
            """;
        cmd.ExecuteNonQuery();
    }

    private static HashSet<int> GetAppliedVersions(SqliteConnection connection)
    {
        var versions = new HashSet<int>();

        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT version FROM schema_migrations";

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            versions.Add(reader.GetInt32(0));
        }

        return versions;
    }

    private static void ApplyMigration(SqliteConnection connection, int version, string name, string sql)
    {
        using var transaction = connection.BeginTransaction();

        try
        {
            // Execute the migration SQL
            using (var cmd = connection.CreateCommand())
            {
                cmd.Transaction = transaction;
                cmd.CommandText = sql;
                cmd.ExecuteNonQuery();
            }

            // Record the migration
            using (var cmd = connection.CreateCommand())
            {
                cmd.Transaction = transaction;
                cmd.CommandText = """
                    INSERT INTO schema_migrations (version, name, applied_at_utc)
                    VALUES (@version, @name, @appliedAt)
                    """;
                cmd.Parameters.AddWithValue("@version", version);
                cmd.Parameters.AddWithValue("@name", name);
                cmd.Parameters.AddWithValue("@appliedAt", DateTime.UtcNow.ToString("O"));
                cmd.ExecuteNonQuery();
            }

            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }

    private static List<(int Version, string Name, string Sql)> GetMigrationResources()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceNames = assembly.GetManifestResourceNames()
            .Where(n => n.EndsWith(".sql", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var migrations = new List<(int Version, string Name, string Sql)>();
        var versionRegex = new Regex(@"(\d{3})_(.+)\.sql$", RegexOptions.IgnoreCase);

        foreach (var resourceName in resourceNames)
        {
            var match = versionRegex.Match(resourceName);
            if (!match.Success)
                continue;

            var version = int.Parse(match.Groups[1].Value);
            var name = match.Groups[0].Value;

            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream is null)
                continue;

            using var reader = new StreamReader(stream);
            var sql = reader.ReadToEnd();

            migrations.Add((version, name, sql));
        }

        return migrations;
    }
}
