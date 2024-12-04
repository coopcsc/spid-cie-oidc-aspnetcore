using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace Spid.Cie.OIDC.AspNetCore.Models;

[ExcludeFromCodeCoverage]
public class OPMetadata_SpidCieOIDCConfiguration
{
    [JsonPropertyName("openid_provider")]
    public OpenIdConnectConfiguration? OpenIdProvider { get; set; }
}
