using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace Spid.Cie.OIDC.AspNetCore.Models.OIDCFederation.TrustMarks;

[ExcludeFromCodeCoverage]
public class TrustMarkGovernmentIndex
{
    [JsonPropertyName("ipa_code")]
    public string? Code { get; set; }
}