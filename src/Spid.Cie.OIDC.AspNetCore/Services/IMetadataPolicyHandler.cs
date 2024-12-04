using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Spid.Cie.OIDC.AspNetCore.Services;

public interface IMetadataPolicyHandler
{
    OpenIdConnectConfiguration? ApplyMetadataPolicy(string opDecodedJwt, string metadataPolicy);
}
