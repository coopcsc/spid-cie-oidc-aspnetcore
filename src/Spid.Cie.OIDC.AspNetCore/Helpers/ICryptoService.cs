﻿using Microsoft.IdentityModel.Tokens;
using Spid.Cie.OIDC.AspNetCore.Models;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Spid.Cie.OIDC.AspNetCore.Helpers;

internal interface ICryptoService
{
    string CreateJWT(RSA publicKey, RSA privateKey, Dictionary<string, object> headers, Dictionary<string, object> claims);
    RsaSecurityKey CreateRsaSecurityKey(int keySize = 2048);
    string DecodeJose(string jose, RSA privateKey);
    string DecodeJWT(string jwt);
    string DecodeJWTHeader(string jwt);
    JWKS GetJWKS(JsonWebKeySet jwks);
    Models.JsonWebKey GetPrivateJWK(Microsoft.IdentityModel.Tokens.JsonWebKey jwk);
    Models.JsonWebKey GetPublicJWK(Microsoft.IdentityModel.Tokens.JsonWebKey jwk);
    (RSA publicKey, RSA privateKey) GetRSAKeys(Microsoft.IdentityModel.Tokens.JsonWebKey key);
    RSA GetRSAPublicKey(Models.JsonWebKey key);
    string JWTEncode(RPEntityConfiguration entityConfiguration, Microsoft.IdentityModel.Tokens.JsonWebKey key);
    string ValidateJWTSignature(string jwt, RSA publicKey);
}
