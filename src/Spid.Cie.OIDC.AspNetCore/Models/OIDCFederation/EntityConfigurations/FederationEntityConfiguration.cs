using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace Spid.Cie.OIDC.AspNetCore.Models;

[ExcludeFromCodeCoverage]
public class FederationEntityConfiguration : ConfigurationBaseInfo
{
    [JsonPropertyName("jwks")]
    public JWKS? JWKS { get; set; }
}
