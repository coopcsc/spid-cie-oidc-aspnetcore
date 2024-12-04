using Microsoft.Extensions.Configuration;
using Spid.Cie.OIDC.AspNetCore.Enums;
using Spid.Cie.OIDC.AspNetCore.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Spid.Cie.OIDC.AspNetCore.Helpers;

public static class OptionsHelpers
{
    internal static SpidCieConfiguration CreateFromConfiguration(IConfiguration configuration)
    {
        return CreateFromConfiguration(configuration, new SpidCieConfiguration());
    }
    public static SpidCieConfiguration CreateFromConfiguration(IConfiguration configuration, SpidCieConfiguration options)
    {
        var section = configuration.GetSection("SpidCie");
        // FIX: necessary to OrchardCore, because options object is taked from DI context and persisted ... we need to not create a new object
        options.RequestRefreshToken = section?.GetValue<bool?>("RequestRefreshToken") ?? false;
        options.SpidOPs = section?.GetSection("SpidOPs")?.Get<List<string>?>() ?? new List<string>();
        options.CieOPs = section?.GetSection("CieOPs")?.Get<List<string>?>() ?? new List<string>();

        if (section is null)
            return options;

        foreach (var relyingPartySection in section
               .GetSection("RelyingParties")?
               .GetChildren()?
               .ToList() ?? Enumerable.Empty<IConfigurationSection>())
        {
            var securityLevel = relyingPartySection.GetValue<int?>("SecurityLevel") ?? 2;
            var relyingParty = new RelyingParty
            {
                Id = relyingPartySection.GetValue<string?>("Id") ?? string.Empty,
                Name = relyingPartySection.GetValue<string?>("Name") ?? string.Empty,
                OrganizationName = relyingPartySection.GetValue<string?>("OrganizationName") ?? string.Empty,
                OrganizationType = relyingPartySection.GetValue<string?>("OrganizationType") ?? string.Empty,
                HomepageUri = relyingPartySection.GetValue<string?>("HomepageUri") ?? string.Empty,
                LogoUri = relyingPartySection.GetValue<string?>("LogoUri") ?? string.Empty,
                PolicyUri = relyingPartySection.GetValue<string?>("PolicyUri") ?? string.Empty,
                SecurityLevel = securityLevel == 1 ? SecurityLevels.L1 : securityLevel == 3 ? SecurityLevels.L3 : SecurityLevels.L2,
                Contacts = relyingPartySection.GetSection("Contacts").Get<List<string>?>() ?? new List<string>(),
                RedirectUris = new List<string>() { $"{(relyingPartySection.GetValue<string?>("Id") ?? string.Empty).RemoveTrailingSlash()}{SpidCieConst.CallbackPath}" },
                LongSessionsEnabled = relyingPartySection.GetValue<bool?>("LongSessionsEnabled") ?? false,
                AuthorityHints = relyingPartySection.GetSection("AuthorityHints").Get<List<string>?>() ?? new List<string>(),
                TrustMarks = relyingPartySection.GetSection("TrustMarks").GetChildren()
                    .Select(trustMarksSection => new TrustMarkDefinition()
                    {
                        Id = trustMarksSection.GetValue<string>("Id"),
                        Issuer = trustMarksSection.GetValue<string>("Issuer"),
                        TrustMark = trustMarksSection.GetValue<string>("TrustMark")
                    }).ToList(),
                OpenIdFederationCertificates = relyingPartySection.GetSection("OpenIdFederationCertificates").GetChildren()
                    .Select(GetCertificate)
                    .ToList(),
                OpenIdCoreCertificates = relyingPartySection.GetSection("OpenIdCoreCertificates").GetChildren().Select(GetOpenIdCoreCertificate).ToList(),
                RequestedClaims = (relyingPartySection.GetSection("RequestedClaims").Get<List<string>?>() ?? new List<string>())
                    .Select(c => ClaimTypes.FromName(c))
                    .ToList()
            };

            options.RelyingParties.Add(relyingParty);
        }

        foreach (var aggregatorSection in section
               .GetSection("Aggregators")?
               .GetChildren()?
               .ToList() ?? Enumerable.Empty<IConfigurationSection>())
        {
            var aggregator = new Aggregator
            {
                Id = aggregatorSection.GetValue<string?>("Id") ?? string.Empty,
                Name = aggregatorSection.GetValue<string?>("Name") ?? string.Empty,
                OrganizationName = aggregatorSection.GetValue<string?>("OrganizationName") ?? string.Empty,
                HomepageUri = aggregatorSection.GetValue<string?>("HomepageUri") ?? string.Empty,
                LogoUri = aggregatorSection.GetValue<string?>("LogoUri") ?? string.Empty,
                PolicyUri = aggregatorSection.GetValue<string?>("PolicyUri") ?? string.Empty,
                Contacts = aggregatorSection.GetSection("Contacts").Get<List<string>?>() ?? new List<string>(),
                AuthorityHints = aggregatorSection.GetSection("AuthorityHints").Get<List<string>?>() ?? new List<string>(),
                OrganizationType = aggregatorSection.GetValue<string?>("OrganizationType") ?? string.Empty,
                Extension = aggregatorSection.GetValue<string?>("Extension") ?? string.Empty,
                TrustMarks = aggregatorSection.GetSection("TrustMarks").GetChildren()
                    .Select(trustMarksSection => new TrustMarkDefinition()
                    {
                        Id = trustMarksSection.GetValue<string>("Id"),
                        Issuer = trustMarksSection.GetValue<string>("Issuer"),
                        TrustMark = trustMarksSection.GetValue<string>("TrustMark")
                    }).ToList(),
                //OpenIdCoreCertificates = aggregatorSection.GetSection("OpenIdCoreCertificates").GetChildren()
                //    .Select(GetCertificate)
                //    .ToList(),
                OpenIdFederationCertificates = aggregatorSection.GetSection("OpenIdFederationCertificates").GetChildren()
                    .Select(GetCertificate)
                    .ToList(),
                MetadataPolicy = JsonDocument.Parse(SerializationHelpers.Serialize(aggregatorSection.GetSection("MetadataPolicy"))?.ToString() ?? "{}")
            };

            foreach (var relyingPartySection in aggregatorSection
               .GetSection("RelyingParties")?
               .GetChildren()?
               .ToList() ?? Enumerable.Empty<IConfigurationSection>())
            {
                var securityLevel = relyingPartySection.GetValue<int?>("SecurityLevel") ?? 2;
                var relyingParty = new RelyingParty
                {
                    Id = relyingPartySection.GetValue<string?>("Id") ?? string.Empty,
                    SecurityLevel = securityLevel == 1 ? SecurityLevels.L1 : securityLevel == 3 ? SecurityLevels.L3 : SecurityLevels.L2,
                    Contacts = relyingPartySection.GetSection("Contacts").Get<List<string>?>() ?? new List<string>(),
                    RedirectUris = new List<string>() { $"{(relyingPartySection.GetValue<string?>("Id") ?? string.Empty).RemoveTrailingSlash()}{SpidCieConst.CallbackPath}" },
                    OrganizationType = relyingPartySection.GetValue<string?>("OrganizationType") ?? string.Empty,
                    Name = relyingPartySection.GetValue<string?>("Name") ?? string.Empty,
                    OrganizationName = relyingPartySection.GetValue<string?>("OrganizationName") ?? string.Empty,
                    HomepageUri = relyingPartySection.GetValue<string?>("HomepageUri") ?? string.Empty,
                    LogoUri = relyingPartySection.GetValue<string?>("LogoUri") ?? string.Empty,
                    PolicyUri = relyingPartySection.GetValue<string?>("PolicyUri") ?? string.Empty,
                    LongSessionsEnabled = relyingPartySection.GetValue<bool?>("LongSessionsEnabled") ?? false,
                    AuthorityHints = new List<string>() { aggregator.Id },
                    TrustMarks = relyingPartySection.GetSection("TrustMarks").GetChildren()
                        .Select(trustMarksSection => new TrustMarkDefinition()
                        {
                            Id = trustMarksSection.GetValue<string>("Id"),
                            Issuer = trustMarksSection.GetValue<string>("Issuer"),
                            TrustMark = trustMarksSection.GetValue<string>("TrustMark")
                        }).ToList(),
                    OpenIdFederationCertificates = aggregator.OpenIdFederationCertificates,
                    //OpenIdCoreCertificates = aggregator.OpenIdCoreCertificates,
                    OpenIdCoreCertificates = relyingPartySection.GetSection("OpenIdCoreCertificates").GetChildren().Select(GetOpenIdCoreCertificate).ToList(),
                    RequestedClaims = (relyingPartySection.GetSection("RequestedClaims").Get<List<string>?>() ?? new List<string>())
                        .Select(c => ClaimTypes.FromName(c))
                        .ToList()
                };

                aggregator.RelyingParties.Add(relyingParty);
            }

            options.Aggregators.Add(aggregator);
        }

        return options;
    }

    static X509Certificate2 GetCertificate(IConfigurationSection openIdFederationCertificatesSection)
    {
        var certificateSource = openIdFederationCertificatesSection.GetValue<string>("Source");
        if (certificateSource.Equals("File", System.StringComparison.OrdinalIgnoreCase))
        {
            var storeConfiguration = openIdFederationCertificatesSection.GetSection("File");
            var path = storeConfiguration.GetValue<string>("Path");
            var password = storeConfiguration.GetValue<string>("Password");
            return X509Helpers.GetCertificateFromFile(path, password);
        }
        else if (certificateSource.Equals("Raw", System.StringComparison.OrdinalIgnoreCase))
        {
            var storeConfiguration = openIdFederationCertificatesSection.GetSection("Raw");
            var certificate = storeConfiguration.GetValue<string>("Certificate");
            var key = storeConfiguration.GetValue<string>("Password");
            return X509Helpers.GetCertificateFromStrings(certificate, key);
        }

        throw new System.Exception($"Invalid Certificate Source {certificateSource}");
    }

    static RPOpenIdCoreCertificate GetOpenIdCoreCertificate(IConfigurationSection openIdFederationCertificatesSection)
    {
        var certificateSource = openIdFederationCertificatesSection.GetValue<string>("Source");

        if (string.IsNullOrWhiteSpace(certificateSource))
            throw new Exception("Certificate Source is required!");

        if (certificateSource.Equals("File", StringComparison.OrdinalIgnoreCase))
        {
            var storeConfiguration = openIdFederationCertificatesSection.GetSection("File");
            var path = storeConfiguration.GetValue<string>("Path");
            var password = storeConfiguration.GetValue<string>("Password");
            var algorithm = storeConfiguration.GetValue<string>("Algorithm");
            var keyUsage = storeConfiguration.GetValue<KeyUsageTypes>("KeyUsage");

            return new RPOpenIdCoreCertificate
            {
                Algorithm = algorithm!,
                Certificate = X509Helpers.GetCertificateFromFile(path!, password!),
                KeyUsage = keyUsage
            };
        }
        else if (certificateSource.Equals("Raw", StringComparison.OrdinalIgnoreCase))
        {
            var storeConfiguration = openIdFederationCertificatesSection.GetSection("Raw");
            var certificate = storeConfiguration.GetValue<string>("Certificate");
            var key = storeConfiguration.GetValue<string>("Password");
            var algorithm = storeConfiguration.GetValue<string>("Algorithm");
            var keyUsage = storeConfiguration.GetValue<KeyUsageTypes>("KeyUsage");

            return new RPOpenIdCoreCertificate
            {
                Algorithm = algorithm!,
                Certificate = X509Helpers.GetCertificateFromStrings(certificate!, key!),
                KeyUsage = keyUsage
            };
        }

        throw new Exception($"Invalid Certificate Source {certificateSource}");
    }
}
