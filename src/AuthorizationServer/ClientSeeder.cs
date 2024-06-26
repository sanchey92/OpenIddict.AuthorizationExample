using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthorizationServer;

public class ClientSeeder(IServiceProvider serviceProvider)
{
    public async Task AddScopes()
    {
        await using var scope = serviceProvider.CreateAsyncScope();
       
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var apiScope = await manager.FindByNameAsync("api1");

        if (apiScope != null)
        {
            await manager.DeleteAsync(apiScope);
        }

        await manager.CreateAsync(new OpenIddictScopeDescriptor
        {
            DisplayName = "Api scope",
            Name = "api1",
            Resources = { "resource_server_1" }
        });

    }

    public async Task AddClients()
    {
        await using var scope = serviceProvider.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        await context.Database.EnsureCreatedAsync();

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var client = await manager.FindByClientIdAsync("web-client");

        if (client != null)
        {
            await manager.DeleteAsync(client);
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "web-client",
            ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
            ConsentType = ConsentTypes.Explicit,
            DisplayName = "Postman client application",
            RedirectUris =
            {
                new Uri("https://localhost:7002/swagger/oauth2-redirect.html")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://localhost:7002/resources")
            },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Logout,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                $"{Permissions.Prefixes.Scope}api1"
            },
            //Requirements =
            //{
            //    Requirements.Features.ProofKeyForCodeExchange
            //}
        });
    }
}