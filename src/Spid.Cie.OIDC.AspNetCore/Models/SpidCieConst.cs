﻿using System;
using System.Diagnostics.CodeAnalysis;

namespace Spid.Cie.OIDC.AspNetCore.Models;

/// <summary>
/// Default values related to Spid authentication handler
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class SpidCieConst
{
    /// <summary>
    /// The default authentication type used when registering the SpidHandler.
    /// </summary>
    public const string AuthenticationScheme = "CIE";

    /// <summary>
    /// The default display name used when registering the SpidHandler.
    /// </summary>
    public const string DisplayName = "CIE";

    /// <summary>
    /// Constant used to identify userstate inside AuthenticationProperties that have been serialized in the 'wctx' parameter.
    /// </summary>
    public const string UserstatePropertiesKey = "SpidCieOIDC.Userstate";

    /// <summary>
    /// The cookie name
    /// </summary>
    public const string CookieName = "SpidCieOIDC.Properties";

    public const string SpidLevelBaseURI = "https://www.spid.gov.it/";
    public const string SpidL1 = $"{SpidLevelBaseURI}{nameof(SpidL1)}";
    public const string SpidL2 = $"{SpidLevelBaseURI}{nameof(SpidL2)}";
    public const string SpidL3 = $"{SpidLevelBaseURI}{nameof(SpidL3)}";
    public const string DefaultAcr = SpidL2;

    public const string ResponseType = "code";

    public const string AuthorizationCode = "authorization_code";

    public const string RefreshToken = "refresh_token";

    public const string OpenIdScope = "openid";

    public const string OfflineScope = "offline_access";

    public const string Prompt = "consent login";

    public const string JWKGeneratorPath = "generatejwk";

    public const string JWKGeneratorContentType = "application/json";

    public const string OPListPath = "list/?type=openid_provider";

    public const string EntityConfigurationPath = ".well-known/openid-federation";
    public const string JsonEntityConfigurationPath = ".well-known/openid-federation/json";

    public const string ResolveEndpointPath = "resolve";

    public const string FetchEndpointPath = "fetch";

    public const string ListEndpointPath = "list";

    public const string TrustMarkStatusEndpointPath = "trust_mark_status";


    public const string EntityConfigurationContentType = "application/entity-statement+jwt";
    public const string JsonContentType = "application/json";

    public const string ResolveContentType = "application/resolve-response+jwt";

    public const int EntityConfigurationExpirationInMinutes = 2880;

    public static TimeSpan TrustChainExpirationGracePeriod = TimeSpan.FromHours(24);

    public const string RPApplicationType = "web";

    public const string RPClientRegistrationType = "automatic";

    public const string RPSubjectType = "pairwise";

    public const string RequestParameter = "request";

    public const string ClientId = "client_id";

    public const string ResponseTypeParameter = "response_type";

    public const string Scope = "scope";

    public const string CodeChallenge = "code_challenge";

    public const string CodeChallengeMethod = "code_challenge_method";

    public const string Nonce = "nonce";

    public const string PromptParameter = "prompt";

    public const string RedirectUri = "redirect_uri";

    public const string AcrValues = "acr_values";

    public const string State = "state";

    public const string Claims = "claims";

    public const string Kid = "kid";

    public const string Typ = "typ";

    public const string TypValue = "entity-statement+jwt";

    public const string Iss = "iss";

    public const string Sub = "sub";

    public const string Iat = "iat";

    public const string Exp = "exp";

    public const string Aud = "aud";

    public const string Jti = "jti";

    public const string ClientAssertion = "client_assertion";

    public const string ClientAssertionType = "client_assertion_type";

    public const string ClientAssertionTypeValue = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    public const string Token = "token";

    public const string IdPSelectorKey = "oidcidp";

    public const string RPSelectorKey = "clientId";

    public const string DummyUrl = "https://dummy.org";

    public const string RevocationEndpoint = "revocation_endpoint";

    public const string CallbackPath = "/signin-spidcie";

    public const string SignedOutCallbackPath = "/signout-callback-spidcie";

    public const string RemoteSignOutPath = "/signout-spidcie";

    public const string BackchannelClientName = "SpidCieBackchannel";
}
