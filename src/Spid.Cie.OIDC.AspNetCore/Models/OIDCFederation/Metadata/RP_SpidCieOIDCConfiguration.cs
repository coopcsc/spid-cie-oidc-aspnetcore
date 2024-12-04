using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace Spid.Cie.OIDC.AspNetCore.Models;

[ExcludeFromCodeCoverage]
public class RP_SpidCieOIDCConfiguration
{
    [JsonPropertyName("application_type")]
    public string ApplicationType { get; } = SpidCieConst.RPApplicationType;

    [JsonPropertyName("client_id")]
    public string? ClientId { get; set; }

    [JsonPropertyName("client_registration_types")]
    public List<string> ClientRegistrationTypes { get; } = new() { SpidCieConst.RPClientRegistrationType };

    [JsonPropertyName("jwks")]
    public JWKS? JWKS { get; set; }

    [JsonPropertyName("client_name")]
    public string? ClientName { get; set; }

    //contacts
    /*
	 "contacts": [
                "ops@rp.example.it"
            ]
	 */

    [JsonPropertyName("grant_types")]
    public List<string> GrantTypes { get; set; } = new();

    [JsonPropertyName("redirect_uris")]
    public List<string> RedirectUris { get; set; } = new();

    [JsonPropertyName("response_types")]
    public List<string> ResponseTypes { get; set; } = new();

    [JsonPropertyName("subject_type")]
    public string SubjectType { get; } = SpidCieConst.RPSubjectType;

    [JsonPropertyName("userinfo_encrypted_response_enc")]
    public string? UserinfoEncryptedResponseEnc { get; set; } = "A256CBC-HS512";

    [JsonPropertyName("userinfo_encrypted_response_alg")]
    public string? UserinfoEncryptedResponseAlg { get; set; } = "RSA-OAEP";

    [JsonPropertyName("userinfo_signed_response_alg")]
    public string? UserinfoSignedResponseAlg { get; set; } = "RS256";

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; set; } = "private_key_jwt";

    [JsonPropertyName("id_token_signed_response_alg")]
    public string? IdTokenSignedResponseAlg { get; set; } = "RS256";
}
