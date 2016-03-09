﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Specialized;
using System.Threading.Tasks;
using IdentityServer4.Core.Models;

namespace IdentityServer4.Core.Validation
{
    public interface IIntrospectionRequestValidator
    {
        Task<IntrospectionRequestValidationResult> ValidateAsync(NameValueCollection parameters, Client scope);
    }
}