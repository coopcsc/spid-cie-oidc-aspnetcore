using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Spid.Cie.OIDC.AspNetCore.Configuration;
using Spid.Cie.OIDC.AspNetCore.Enums;
using Spid.Cie.OIDC.AspNetCore.Helpers;
using Spid.Cie.OIDC.AspNetCore.Models;

namespace Spid.Cie.OIDC.AspNetCore.Services.Cache;

sealed class TrustChainCacheWorker(
    ILogger<TrustChainCacheWorker> logger,
    IOptionsMonitor<SpidCieOptions> _options,
    IIdentityProvidersRetriever idpRetriever,
    IRelyingPartiesHandler rpHandler,
    ICryptoService cryptoService,
    ILogPersister logPersister,
    HttpClient httpClient,
    TrustChainCacheSignal<TrustChain<FederationEntityConfiguration>> cacheSignal,
    IMemoryCache cache) : BackgroundService
{
    private readonly TimeSpan _updateInterval = TimeSpan.FromHours(3);

    private bool _isCacheInitialized = false;

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await cacheSignal.WaitAsync();
        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            logger.LogInformation("Updating cache.");

            try
            {
                var idpUrls = _options.CurrentValue.CieOPs.Union(await idpRetriever.GetCieIdentityProviders()).Select(ip => new
                {
                    Type = IdentityProviderTypes.CIE,
                    Url = ip
                }).Union(_options.CurrentValue.SpidOPs.Union(await idpRetriever.GetSpidIdentityProviders()).Select(ip => new
                {
                    Type = IdentityProviderTypes.SPID,
                    Url = ip
                })).ToList();

                foreach (var idp in idpUrls)
                { }

                foreach (var rp in await rpHandler.GetRelyingParties())
                { }

                if (photos is { Length: > 0 })
                {
                    cache.Set("Photos", photos);
                    logger.LogInformation(
                        "Cache updated with {Count:#,#} photos.", photos.Length);
                }
                else
                {
                    logger.LogWarning(
                        "Unable to fetch photos to update cache.");
                }
            }
            finally
            {
                if (!_isCacheInitialized)
                {
                    cacheSignal.Release();
                    _isCacheInitialized = true;
                }
            }

            try
            {
                logger.LogInformation(
                    "Will attempt to update the cache in {Hours} hours from now.",
                    _updateInterval.Hours);

                await Task.Delay(_updateInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                logger.LogWarning("Cancellation acknowledged: shutting down.");
                break;
            }
        }
    }

    public async Task<TrustChain<RPEntityConfiguration>?> BuildRPTrustChain(string url)
    {
        List<string> trustChain = new();
        string? trustAnchorUsed = default;

        try
        {
            (RPEntityConfiguration? rpConf, string? decodedRPJwt, string? rpJwt) = await ValidateAndDecodeEntityConfiguration<RPEntityConfiguration>(url);

            if (rpConf is null || rpJwt is null || rpConf.ExpiresOn < DateTime.UtcNow)
            {
                logger.LogWarning($"EntityConfiguration not retrieved for RP {url}");

                return default;
            }

            bool rpValidated = false;
            DateTimeOffset expiresOn = rpConf.ExpiresOn;

            foreach (var saHint in rpConf.AuthorityHints ?? new())
            {
                trustChain.Clear();

                (SAEntityConfiguration? saConf, string? decodedSAJwt, string? saJwt) = await ValidateAndDecodeEntityConfiguration<SAEntityConfiguration>(saHint);

                if (saConf is null || saJwt is null || saConf.Metadata is null || saConf.Metadata.FederationEntity is null || saConf.ExpiresOn < DateTime.UtcNow)
                {
                    logger.LogWarning($"EntityConfiguration not retrieved for SA {saHint}");

                    continue;
                }

                trustChain.Add(saJwt);

                if (saConf.ExpiresOn < expiresOn)
                    expiresOn = saConf.ExpiresOn;

                var saFetchUrl = $"{saConf.Metadata.FederationEntity.FederationFetchEndpoint}?sub={url}";
                (EntityStatement? rpEntityStatement, string? decodedRPEsJwt, string? esRPJwt) = await GetAndValidateEntityStatement(saFetchUrl, rpJwt);

                if (rpEntityStatement is null || esRPJwt is null || rpEntityStatement.ExpiresOn < DateTime.UtcNow)
                {
                    logger.LogWarning($"EntityStatement not retrieved for RP {url}");
                    continue;
                }

                trustChain.Add(esRPJwt);

                if (rpEntityStatement.ExpiresOn < expiresOn)
                    expiresOn = rpEntityStatement.ExpiresOn;

                foreach (var taHint in saConf.AuthorityHints ?? new())
                {
                    (TAEntityConfiguration? taConf, string? decodedTAJwt, string? taJwt) = await ValidateAndDecodeEntityConfiguration<TAEntityConfiguration>(taHint);

                    if (taConf is null || taJwt is null || taConf.Metadata is null || taConf.Metadata.FederationEntity is null || taConf.ExpiresOn < DateTime.UtcNow)
                    {
                        logger.LogWarning($"EntityConfiguration not retrieved for TA {taHint}");

                        continue;
                    }

                    trustChain.Add(taJwt);

                    if (taConf.ExpiresOn < expiresOn)
                        expiresOn = taConf.ExpiresOn;

                    var taFetchUrl = $"{taConf.Metadata.FederationEntity.FederationFetchEndpoint}?sub={saConf.Subject}";
                    (EntityStatement? saEntityStatement, string? decodedSAEsJwt, string? esSAJwt) = await GetAndValidateEntityStatement(taFetchUrl, saJwt);

                    if (saEntityStatement is null || esSAJwt is null || saEntityStatement.ExpiresOn < DateTime.UtcNow)
                    {
                        logger.LogWarning($"EntityStatement not retrieved for SA {saConf.Subject}");
                        continue;
                    }

                    trustChain.Add(esSAJwt);
                    trustChain.Add(rpJwt);

                    if (saEntityStatement.ExpiresOn < expiresOn)
                        expiresOn = saEntityStatement.ExpiresOn;

                    rpValidated = true;
                    trustAnchorUsed = taHint;
                    break;
                }
            }

            if (rpValidated && rpConf is not null && trustAnchorUsed is not null)
            {
                return new TrustChain<RPEntityConfiguration>()
                {
                    ExpiresOn = expiresOn,
                    EntityConfiguration = rpConf,
                    Chain = trustChain,
                    TrustAnchorUsed = trustAnchorUsed
                };
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, ex.Message);
            throw;
        }

        return default;
    }


    public async Task<TrustChain<OPEntityConfiguration>?> BuildTrustChain(string url)
    {
        try
        {
            List<string> trustChain = new();
            string? trustAnchorUsed = default;

            (OPEntityConfiguration? opConf, string? decodedOPJwt, string? opJwt) = await ValidateAndDecodeEntityConfiguration<OPEntityConfiguration>(url);
            if (opConf is null || opJwt is null || opConf.ExpiresOn < DateTime.UtcNow)
            {
                logger.LogWarning($"EntityConfiguration not retrieved for OP {url}");
                return default;
            }

            DateTimeOffset expiresOn = opConf.ExpiresOn;

            bool opValidated = false;
            foreach (var authorityHint in opConf.AuthorityHints ?? new())
            {
                trustChain.Clear();

                (TAEntityConfiguration? taConf, string? decodedTAJwt, string? taJwt) = await ValidateAndDecodeEntityConfiguration<TAEntityConfiguration>(authorityHint);
                if (taConf is null || taJwt is null || taConf.ExpiresOn < DateTime.UtcNow)
                {
                    logger.LogWarning($"EntityConfiguration not retrieved for TA {authorityHint}");
                    continue;
                }

                trustChain.Add(taJwt);

                if (taConf.ExpiresOn < expiresOn)
                    expiresOn = taConf.ExpiresOn;

                var fetchUrl = $"{taConf.Metadata.FederationEntity.FederationFetchEndpoint}?sub={url}";
                (EntityStatement? entityStatement, string? decodedEsJwt, string? esJwt) = await GetAndValidateEntityStatement(fetchUrl, opJwt);

                if (entityStatement is null || esJwt is null || entityStatement.ExpiresOn < DateTime.UtcNow)
                {
                    logger.LogWarning($"EntityStatement not retrieved for OP {url}");
                    continue;
                }

                trustChain.Add(esJwt);

                var esExpiresOn = entityStatement.ExpiresOn;

                // Apply policy
                //opConf!.Metadata!.OpenIdProvider = _metadataPolicyHandler.ApplyMetadataPolicy(decodedOPJwt!, entityStatement.MetadataPolicy.ToJsonString());

                if (opConf!.Metadata!.OpenIdProvider is not null)
                {
                    if (!string.IsNullOrWhiteSpace(opConf!.Metadata!.OpenIdProvider.JwksUri))
                    {
                        var keys = await httpClient.GetStringAsync(opConf!.Metadata!.OpenIdProvider.JwksUri);
                        if (!string.IsNullOrWhiteSpace(keys))
                        {
                            opConf!.Metadata!.OpenIdProvider.JsonWebKeySet = JsonConvert.DeserializeObject<JsonWebKeySet>(keys);
                        }
                    }
                    else if (!string.IsNullOrWhiteSpace(JObject.Parse(decodedOPJwt)["metadata"]["openid_provider"]["jwks"].ToString()))
                    {
                        opConf!.Metadata!.OpenIdProvider.JsonWebKeySet = JsonWebKeySet.Create(JObject.Parse(decodedOPJwt)["metadata"]["openid_provider"]["jwks"].ToString());
                    }
                    if (opConf!.Metadata!.OpenIdProvider.JsonWebKeySet is null)
                    {
                        logger.LogWarning($"No jwks found for the OP {url} validated by the authorityHint {authorityHint}");
                        continue;
                    }

                    foreach (SecurityKey key in opConf!.Metadata!.OpenIdProvider.JsonWebKeySet.GetSigningKeys())
                    {
                        opConf!.Metadata!.OpenIdProvider.SigningKeys.Add(key);
                    }
                }


                if (opConf is not null && opConf.Metadata?.OpenIdProvider is not null)
                {
                    trustChain.Add(opJwt);

                    expiresOn = esExpiresOn < expiresOn ? esExpiresOn : expiresOn;
                    opValidated = true;
                    trustAnchorUsed = authorityHint;
                    break;
                }
            }
            if (opValidated && opConf is not null && trustAnchorUsed is not null)
            {
                return new TrustChain<OPEntityConfiguration>()
                {
                    ExpiresOn = expiresOn,
                    EntityConfiguration = opConf,
                    //OpConf = opConf,
                    Chain = trustChain,
                    TrustAnchorUsed = trustAnchorUsed
                };
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, ex.Message);
            throw;
        }

        return default;
    }

    private async Task<(T? conf, string? decodedJwt, string? jwt)> ValidateAndDecodeEntityConfiguration<T>(string? url)
        where T : FederationEntityConfiguration
    {
        try
        {
            Throw<Exception>.If(string.IsNullOrWhiteSpace(url), "Url parameter is not defined");

            var metadataAddress = $"{url.EnsureTrailingSlash()!}{SpidCieConst.EntityConfigurationPath}";
            var jwt = await httpClient.GetStringAsync(metadataAddress);
            Throw<Exception>.If(string.IsNullOrWhiteSpace(jwt), $"EntityConfiguration JWT not retrieved from url {metadataAddress}");

            await logPersister.LogGetEntityConfiguration(metadataAddress, jwt);

            var decodedJwt = cryptoService.DecodeJWT(jwt);
            Throw<Exception>.If(string.IsNullOrWhiteSpace(decodedJwt), $"Invalid EntityConfiguration JWT for url {metadataAddress}: {jwt}");

            var conf = System.Text.Json.JsonSerializer.Deserialize<T>(decodedJwt);
            Throw<Exception>.If(conf is null, $"Invalid Decoded EntityConfiguration JWT for url {metadataAddress}: {decodedJwt}");

            var decodedJwtHeader = cryptoService.DecodeJWTHeader(jwt);
            Throw<Exception>.If(string.IsNullOrWhiteSpace(decodedJwtHeader), $"Invalid EntityConfiguration JWT Header for url {metadataAddress}: {jwt}");

            var header = JObject.Parse(decodedJwtHeader);
            var kid = (string)header[SpidCieConst.Kid];
            Throw<Exception>.If(string.IsNullOrWhiteSpace(kid), $"No Kid specified in the EntityConfiguration JWT Header for url {metadataAddress}: {decodedJwtHeader}");

            var key = conf!.JWKS.Keys.FirstOrDefault(k => k.Kid.Equals(kid, StringComparison.InvariantCultureIgnoreCase));
            Throw<Exception>.If(key is null, $"No key found with kid {kid} for url {metadataAddress}: {decodedJwtHeader}");

            RSA publicKey = cryptoService.GetRSAPublicKey(key!);
            Throw<Exception>.If(!decodedJwt.Equals(cryptoService.ValidateJWTSignature(jwt, publicKey)),
                $"Invalid Signature for the EntityConfiguration JWT retrieved at the url {metadataAddress}: {decodedJwtHeader}");

            return (conf, decodedJwt, jwt);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, ex.Message);
            return default;
        }
    }

    private async Task<(EntityStatement?, string? decodedEsJwt, string esJwt)> GetAndValidateEntityStatement(string? url, string opJwt)
    {
        try
        {
            Throw<Exception>.If(string.IsNullOrWhiteSpace(url), "Url parameter is not defined");

            var esJwt = await httpClient.GetStringAsync(url);
            Throw<Exception>.If(string.IsNullOrWhiteSpace(esJwt), $"EntityStatement JWT not retrieved from url {url}");

            await logPersister.LogGetEntityStatement(url!, esJwt);

            var decodedEsJwt = cryptoService.DecodeJWT(esJwt);
            Throw<Exception>.If(string.IsNullOrWhiteSpace(decodedEsJwt), $"Invalid EntityStatement JWT for url {url}: {esJwt}");

            var entityStatement = System.Text.Json.JsonSerializer.Deserialize<EntityStatement>(decodedEsJwt);
            Throw<Exception>.If(entityStatement is null, $"Invalid Decoded EntityStatement JWT for url {url}: {decodedEsJwt}");

            var decodedOpJwtHeader = cryptoService.DecodeJWTHeader(opJwt);
            Throw<Exception>.If(string.IsNullOrWhiteSpace(decodedOpJwtHeader), $"Invalid EntityConfiguration JWT Header: {opJwt}");

            var opHeader = JObject.Parse(decodedOpJwtHeader);
            var kid = (string)opHeader[SpidCieConst.Kid];
            Throw<Exception>.If(string.IsNullOrWhiteSpace(kid), $"No Kid specified in the EntityConfiguration JWT Header: {decodedOpJwtHeader}");

            var key = entityStatement!.JWKS.Keys.FirstOrDefault(k => k.Kid.Equals(kid, StringComparison.InvariantCultureIgnoreCase));
            Throw<Exception>.If(key is null, $"No key found with kid {kid} in the EntityStatement at url {url}: {decodedEsJwt}");

            RSA publicKey = cryptoService.GetRSAPublicKey(key!);
            var decodedOpJwt = cryptoService.DecodeJWT(opJwt);
            Throw<Exception>.If(!decodedOpJwt.Equals(cryptoService.ValidateJWTSignature(opJwt, publicKey)),
                $"Invalid Signature for the EntityConfiguration JWT verified with the EntityStatement at url {url}: EntityConfiguration JWT {opJwt} - EntityStatement JWT {esJwt}");

            return (entityStatement, decodedEsJwt, esJwt);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, ex.Message);
            return default;
        }
    }
}

internal class CacheSignal<T>
{
}