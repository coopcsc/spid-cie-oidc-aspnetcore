using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Spid.Cie.OIDC.AspNetCore.Models;
using System.Linq;
using System.Threading.Tasks;

namespace Spid.Cie.OIDC.AspNetCore.Services.Defaults;

public class DefaultIdentityProviderSelector : IIdentityProviderSelector
{
    private readonly IIdentityProvidersHandler _idpHandler;
    private readonly IHttpContextAccessor _httpContextAccessor;
    //TODO: remove me, logging for #497
    private readonly ILogger<DefaultIdentityProviderSelector> _logger;

    public DefaultIdentityProviderSelector(IHttpContextAccessor httpContextAccessor, IIdentityProvidersHandler idpHandler,
    ILogger<DefaultIdentityProviderSelector> logger)
    {
        _idpHandler = idpHandler;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task<IdentityProvider?> GetSelectedIdentityProvider()
    {
        var identityProviders = await _idpHandler.GetIdentityProviders();
        var provider = (string?)_httpContextAccessor.HttpContext!.Request.Query[SpidCieConst.IdPSelectorKey]
            ?? (string?)_httpContextAccessor.HttpContext!.Items[SpidCieConst.IdPSelectorKey];

        //TODO: remove me, logging for #497
        _logger.LogInformation($"provider: {provider} - IdP: {identityProviders.Count()}");
        if (!string.IsNullOrWhiteSpace(provider))
            return identityProviders.FirstOrDefault(idp => (idp?.Uri ?? "").Equals(provider, System.StringComparison.InvariantCultureIgnoreCase));

        return default;
    }
}
