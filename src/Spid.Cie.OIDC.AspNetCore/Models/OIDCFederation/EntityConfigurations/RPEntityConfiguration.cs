using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace Spid.Cie.OIDC.AspNetCore.Models;

[ExcludeFromCodeCoverage]
public class RPEntityConfiguration : ExtendedEntityConfiguration
{
    [JsonPropertyName("metadata")]
    public RPMetadata_SpidCieOIDCConfiguration? Metadata { get; set; }
}
