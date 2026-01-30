using CreatorLedger.Application.Primitives;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Ledger;
using CreatorLedger.Infrastructure.Persistence;
using CreatorLedger.Tests.Fakes;

namespace CreatorLedger.Tests.Integration;

/// <summary>
/// Test fixture for SQLite integration tests.
/// Creates a temporary database file for each test.
/// </summary>
public sealed class SqliteTestFixture : IDisposable
{
    private readonly string _tempDbPath;
    private bool _disposed;

    public SqliteConnectionFactory ConnectionFactory { get; }
    public SqliteCreatorIdentityRepository IdentityRepository { get; }
    public SqliteLedgerRepository LedgerRepository { get; }
    public IClock Clock { get; }

    public SqliteTestFixture()
    {
        // Create a unique temp file for each test run
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"creatorledger_test_{Guid.NewGuid():N}.db");

        ConnectionFactory = new SqliteConnectionFactory(_tempDbPath);
        IdentityRepository = new SqliteCreatorIdentityRepository(ConnectionFactory);
        LedgerRepository = new SqliteLedgerRepository(ConnectionFactory, IdentityRepository);
        Clock = new FakeClock();
    }

    /// <summary>
    /// Gets the path to the test database file.
    /// </summary>
    public string DatabasePath => _tempDbPath;

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        ConnectionFactory.Dispose();

        // Clean up temp file
        try
        {
            if (File.Exists(_tempDbPath))
                File.Delete(_tempDbPath);

            // Also delete WAL and SHM files if they exist
            var walPath = _tempDbPath + "-wal";
            var shmPath = _tempDbPath + "-shm";

            if (File.Exists(walPath))
                File.Delete(walPath);
            if (File.Exists(shmPath))
                File.Delete(shmPath);
        }
        catch
        {
            // Best effort cleanup
        }
    }
}
