using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Spid.Cie.OIDC.AspNetCore.Helpers;
using Spid.Cie.OIDC.AspNetCore.Resources;
using Spid.Cie.OIDC.AspNetCore.Services;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Spid.Cie.OIDC.AspNetCore.Configuration;

public class ConfigurationManager : IConfigurationManager<OpenIdConnectConfiguration>
{
    readonly IIdentityProviderSelector _idpSelector;
    //TODO: remove me, logging for #497
    private readonly ILogger<ConfigurationManager> _logger;

    public ConfigurationManager(IIdentityProviderSelector idpSelector, ILogger<ConfigurationManager> logger)
    {
        _idpSelector = idpSelector;
        _logger = logger;
    }

    public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
    {
        var idp = await _idpSelector.GetSelectedIdentityProvider();

        _logger.LogInformation($"IdP organization name : {idp?.OrganizationName}");
        _logger.LogInformation($"IdP open id provider: {idp?.EntityConfiguration?.Metadata?.OpenIdProvider}");

        Throw<InvalidOperationException>.If(idp is null, ErrorLocalization.IdentityProviderNotFound);

        var idpConf = idp!.EntityConfiguration?.Metadata?.OpenIdProvider;

        _logger.LogInformation($"IdP configuration : {idpConf?.Issuer ?? "NO ONE" }");

        Throw<Exception>.If(idpConf is null, ErrorLocalization.IdentityProviderNotFound);

        return idpConf!;
    }

    public void RequestRefresh() { }
}
