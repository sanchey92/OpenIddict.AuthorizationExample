using System.Collections.Immutable;
using System.Security.Claims;
using System.Web;
using AuthorizationServer.Services;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthorizationServer.Controllers;

[ApiController]
public class AuthorizationController(
    IOpenIddictApplicationManager applicationManager,
    IAuthorizationService authService) : Controller
{
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var parameters = authService.GetOAuthParameters(HttpContext, new List<string> { Parameters.Prompt });

        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (!authService.IsAuthenticated(result, request))
        {
            var redirectUri = authService.BuildRedirectUrl(HttpContext.Request, parameters);

            return Challenge(
                properties: new AuthenticationProperties { RedirectUri = redirectUri },
                new[] { CookieAuthenticationDefaults.AuthenticationScheme });
        }

        var application = await applicationManager.FindByIdAsync(request.ClientId!) ??
                          throw new InvalidOperationException("The calling client application cannot be found.");

        var consentType = await applicationManager.GetConsentTypeAsync(application);

        if (consentType != ConsentTypes.Explicit)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: GetAuthenticationProperties(Errors.InvalidClient, "only explicit clients supported"));
        }

        var consentClaim = result.Principal!.GetClaim(Constants.ConsentNaming);

        if (consentClaim != Constants.GrantAccessValue)
        {
            var redirectUrl = authService.BuildRedirectUrl(HttpContext.Request, parameters);
            var returnUrl = HttpUtility.UrlDecode(redirectUrl);
            var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

            return Redirect(consentRedirectUrl);
        }

        var userId = result.Principal!.FindFirst(ClaimTypes.Email)!.Value;

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        SetClaimsForIdentity(identity, userId);

        identity.SetScopes(request.GetScopes());
        identity.SetDestinations(x => authService.GetDestinations(identity, x));

        var principal = new ClaimsPrincipal(identity);

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/consent/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
        {
            throw new InvalidOperationException("The specified grant type is not supported");
        }

        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var userId = result.Principal!.GetClaim(Claims.Subject);

        if (string.IsNullOrEmpty(userId))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: GetAuthenticationProperties(Errors.InvalidGrant, "Cannot find user from the token"));
        }

        var identity = new ClaimsIdentity(
            result.Principal!.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        SetClaimsForIdentity(identity, userId);

        identity.SetDestinations(x => authService.GetDestinations(identity, x));

        var principal = new ClaimsPrincipal(identity);

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/logout")]
    public async Task<IActionResult> LogoutPost()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = "/" });
    }

    private void SetClaimsForIdentity(ClaimsIdentity identity, string userId)
    {
        identity.SetClaim(Claims.Subject, userId)
            .SetClaim(Claims.Email, userId)
            .SetClaim(Claims.Name, userId)
            .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());
    }

    private AuthenticationProperties GetAuthenticationProperties(string error, string description)
    {
        return new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
        });
    }
}