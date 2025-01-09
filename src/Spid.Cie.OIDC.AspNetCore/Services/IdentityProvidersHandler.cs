using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Spid.Cie.OIDC.AspNetCore.Configuration;
using Spid.Cie.OIDC.AspNetCore.Enums;
using Spid.Cie.OIDC.AspNetCore.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Spid.Cie.OIDC.AspNetCore.Services;

public class IdentityProvidersHandler : IIdentityProvidersHandler
{
    readonly ITrustChainManager _trustChainManager;
    readonly IOptionsMonitor<SpidCieOptions> _options;
    readonly IIdentityProvidersRetriever _idpRetriever;
    readonly ILogger<IdentityProvidersHandler> _logger;

    public IdentityProvidersHandler(IOptionsMonitor<SpidCieOptions> options, IIdentityProvidersRetriever idpRetriever,
                                    ITrustChainManager trustChainManager, ILogger<IdentityProvidersHandler> logger)
    {
        _logger = logger;
        _options = options;
        _idpRetriever = idpRetriever;
        _trustChainManager = trustChainManager;
    }

    public async Task<IEnumerable<IdentityProvider>> GetIdentityProviders()
    {
        List<IdentityProvider?> result = new();

        //TODO: remove me, logging for #497
        _logger.LogInformation($" FROM CONF - CIE OP first: {_options.CurrentValue.CieOPs.FirstOrDefault()} - RelyingParties First Name: {_options.CurrentValue.RelyingParties.FirstOrDefault()?.Name ?? "NO ONE"}");
        _logger.LogInformation($" FROM CONF - SPID OP first: {_options.CurrentValue.SpidOPs.FirstOrDefault()}");

        var idpUrls = _options.CurrentValue.CieOPs.Union(await _idpRetriever.GetCieIdentityProviders()).Select(ip => new
        {
            Type = IdentityProviderTypes.CIE,
            Url = ip
        }).Union(_options.CurrentValue.SpidOPs.Union(await _idpRetriever.GetSpidIdentityProviders()).Select(ip => new
        {
            Type = IdentityProviderTypes.SPID,
            Url = ip
        })).ToList();

        foreach (var idp in idpUrls)
        {
            var idpConf = await _trustChainManager.BuildTrustChain(idp.Url);

            //TODO: remove me, logging for #497
            _logger.LogInformation($" IdP URL: {idp.Url} - conf Subject/Uri: {idpConf?.Subject}, conf Issuer: {idpConf?.Metadata?.OpenIdProvider?.Issuer}");
            if (idpConf != null)
                result.Add(idp.Type == IdentityProviderTypes.CIE ? CreateIdentityProvider<CieIdentityProvider>(idpConf) :
                            CreateIdentityProvider<SpidIdentityProvider>(idpConf));
        }

        return result.Where(r => r != default).ToList()!;
    }

    //TODO: changed in #497 to remove possible NULL remarks
    static T? CreateIdentityProvider<T>(OPEntityConfiguration conf)
        where T : IdentityProvider
    {
        if(conf == null || conf == default)
            return default;

        var openIdProvider = conf?.Metadata?.OpenIdProvider ?? new OpenIdConnectConfiguration();

        return typeof(T).Equals(typeof(SpidIdentityProvider)) ?
            new SpidIdentityProvider()
            {
                EntityConfiguration = conf,
                Uri = conf!.Subject ?? string.Empty,
                OrganizationLogoUrl = openIdProvider.AdditionalData.TryGetValue("logo_uri", out object? spidLogoUri) ? spidLogoUri as string ?? string.Empty : string.Empty,
                OrganizationName = openIdProvider.AdditionalData.TryGetValue("organization_name", out object? spidOrganizationName) ? spidOrganizationName as string ?? string.Empty : string.Empty,
                SupportedAcrValues = openIdProvider.AcrValuesSupported.ToList(),
            } as T :
            typeof(T).Equals(typeof(CieIdentityProvider)) ?
            new CieIdentityProvider()
            {
                EntityConfiguration = conf,
                Uri = conf!.Subject ?? string.Empty,
                OrganizationLogoUrl = openIdProvider.AdditionalData.TryGetValue("logo_uri", out object? cieLogoUri) ? cieLogoUri as string ?? string.Empty : string.Empty,
                OrganizationName = openIdProvider.AdditionalData.TryGetValue("organization_name", out object? cieOrganizationName) ? cieOrganizationName as string ?? string.Empty : string.Empty,
                SupportedAcrValues = openIdProvider.AcrValuesSupported.ToList(),
            } as T : default;
    }
}
