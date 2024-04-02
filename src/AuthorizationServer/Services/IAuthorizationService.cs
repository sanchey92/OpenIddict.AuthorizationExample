using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;

namespace AuthorizationServer.Services;

public interface IAuthorizationService
{
    IDictionary<string, StringValues> GetOAuthParameters(HttpContext httpContext, List<string>? excluding = null);
    string BuildRedirectUrl(HttpRequest request, IDictionary<string, StringValues> oAuthParameters);
    bool IsAuthenticated(AuthenticateResult authenticateResult, OpenIddictRequest request);
    List<string> GetDestinations(ClaimsIdentity identity, Claim claim);
}