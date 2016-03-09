﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Core.Validation;
using IdentityServer4.Core.Services;
using IdentityServer4.Core.ResponseHandling;
using Microsoft.Extensions.Logging;
using IdentityServer4.Core.Extensions;
using IdentityServer4.Core.Events;
using IdentityServer4.Core.Hosting;
using IdentityServer4.Core.Endpoints.Results;
using IdentityModel;

namespace IdentityServer4.Core.Endpoints
{
    public class UserInfoEndpoint : IEndpoint
    {
        private readonly ILogger _logger;
        private readonly IEventService _events;
        private readonly IUserInfoResponseGenerator _generator;
        private readonly IdentityServerContext _context;
        private readonly BearerTokenUsageValidator _tokenUsageValidator;
        private readonly ITokenValidator _tokenValidator;

        public UserInfoEndpoint(IdentityServerContext context, ITokenValidator tokenValidator, IUserInfoResponseGenerator generator, BearerTokenUsageValidator tokenUsageValidator, IEventService events, ILogger<UserInfoEndpoint> logger)
        {

            _context = context;
            _tokenValidator = tokenValidator;
            _tokenUsageValidator = tokenUsageValidator;
            _generator = generator;
            _events = events;
            _logger = logger;
        }

        public async Task<IEndpointResult> ProcessAsync(IdentityServerContext context)
        {
            if (context.HttpContext.Request.Method != "GET" && context.HttpContext.Request.Method != "POST")
            {
                return new StatusCodeResult(405);
            }

            _logger.LogVerbose("Start userinfo request");

            var tokenUsageResult = await _tokenUsageValidator.ValidateAsync(context.HttpContext);
            if (tokenUsageResult.TokenFound == false)
            {
                var error = "No token found.";

                _logger.LogError(error);
                await RaiseFailureEventAsync(error);
                return Error(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }

            _logger.LogInformation("Token found: {token}", tokenUsageResult.UsageType.ToString());

            var issuer = _context.GetIssuerUri();

            var tokenResult = await _tokenValidator.ValidateAccessTokenAsync(
                tokenUsageResult.Token, 
                audience: string.Format(Constants.AccessTokenAudience, issuer.EnsureTrailingSlash()),
                expectedScope : Constants.StandardScopes.OpenId);

            if (tokenResult.IsError)
            {
                _logger.LogError(tokenResult.Error);
                await RaiseFailureEventAsync(tokenResult.Error);
                return Error(tokenResult.Error);
            }

            // pass scopes/claims to profile service
            var subject = tokenResult.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject).Value;
            var scopes = tokenResult.Claims.Where(c => c.Type == JwtClaimTypes.Scope).Select(c => c.Value);

            var payload = await _generator.ProcessAsync(subject, scopes, tokenResult.Client);

            _logger.LogInformation("End userinfo request");
            await RaiseSuccessEventAsync();

            return new UserInfoResult(payload);
        }

        private IEndpointResult Error(string error, string description = null)
        {
            return new ProtectedResourceErrorResult(error, description);
        }

        private async Task RaiseSuccessEventAsync()
        {
            await _events.RaiseSuccessfulEndpointEventAsync(EventConstants.EndpointNames.UserInfo);
        }

        private async Task RaiseFailureEventAsync(string error)
        {
            if (_context.Options.EventsOptions.RaiseFailureEvents)
            {
                await _events.RaiseFailureEndpointEventAsync(EventConstants.EndpointNames.UserInfo, error);
            }
        }
    }
}
