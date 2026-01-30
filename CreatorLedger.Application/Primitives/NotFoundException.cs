namespace CreatorLedger.Application.Primitives;

/// <summary>
/// Exception thrown when a requested entity is not found.
/// </summary>
public class NotFoundException : Exception
{
    public string EntityType { get; }
    public string EntityId { get; }

    public NotFoundException(string entityType, string entityId)
        : base($"{entityType} with id '{entityId}' was not found")
    {
        EntityType = entityType;
        EntityId = entityId;
    }

    public static NotFoundException ForCreator(string id) => new("Creator", id);
    public static NotFoundException ForAsset(string id) => new("Asset", id);
    public static NotFoundException ForAttestation(string id) => new("Attestation", id);
}
