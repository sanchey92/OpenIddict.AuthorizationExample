using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;

namespace AuthorizationServer.Services;

public class AuthorizationService : IAuthorizationService
{
    public IDictionary<string, StringValues> GetOAuthParameters(HttpContext httpContext, List<string>? excluding = null)
    {
        excluding ??= [];

        return httpContext.Request.HasFormContentType
            ? ExtractParameters(httpContext.Request.Form, excluding)
            : ExtractParameters(httpContext.Request.Query, excluding);
    }

    public string BuildRedirectUrl(HttpRequest request, IDictionary<string, StringValues> oAuthParameters)
    {
        var uriBuilder = new UriBuilder
        {
            Scheme = request.Scheme,
            Host = request.Host.Host,
            Path = request.PathBase.Add(request.Path).Value,
            Query = QueryString.Create(oAuthParameters).Value
        };

        if (request.Host.Port.HasValue)
        {
            uriBuilder.Port = request.Host.Port.Value;
        }

        return uriBuilder.ToString();
    }

    public bool IsAuthenticated(AuthenticateResult authenticateResult, OpenIddictRequest request)
    {
        return authenticateResult.Succeeded && IsTokenExpired(authenticateResult, request);
    }

    public List<string> GetDestinations(ClaimsIdentity identity, Claim claim)
    {
        var destinations = new List<string>();

        if (claim.Type is OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.Email)
        {
            destinations.Add(OpenIddictConstants.Destinations.AccessToken);
        }

        return destinations;
    }

    private IDictionary<string, StringValues> ExtractParameters(
        IEnumerable<KeyValuePair<string, StringValues>> collection, IEnumerable<string> excluding)
    {
        return collection
            .Where(x => !excluding.Contains(x.Key))
            .ToDictionary(x => x.Key, x => x.Value);
    }

    private bool IsTokenExpired(AuthenticateResult authenticateResult, OpenIddictRequest request)
    {
        if (!request.MaxAge.HasValue)
        {
            return false;
        }

        if (!authenticateResult.Properties?.IssuedUtc.HasValue ?? true)
        {
            return false;
        }

        var maxAge = TimeSpan.FromSeconds(request.MaxAge.Value);
        var currentUtc = DateTimeOffset.UtcNow;
        var expired = currentUtc - authenticateResult.Properties.IssuedUtc > maxAge;

        return !expired;
    }
}