﻿using Spid.Cie.OIDC.AspNetCore.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Spid.Cie.OIDC.AspNetCore.Services;

internal class DefaultRelyingPartiesRetriever : IRelyingPartiesRetriever
{
    public Task<IEnumerable<RelyingParty>> GetRelyingParties()
    {
        return Task.FromResult(Enumerable.Empty<RelyingParty>());
    }
}
