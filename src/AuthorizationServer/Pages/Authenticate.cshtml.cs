using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthorizationServer.Pages;

public class Authenticate : PageModel
{
    public string Email { get; set; } = Constants.Email;

    public string Password { get; set; } = Constants.Password;

    [BindProperty] public string? ReturnUrl { get; set; }

    public string AuthStatus { get; set; } = "";

    public IActionResult OnGet(string returnUrl)
    {
        ReturnUrl = returnUrl;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string email, string password)
    {
        if (email != Constants.Email || password != Constants.Password)
        {
            AuthStatus = "Invalid email or password";
            return Page();
        }

        var claims = new List<Claim> { new(ClaimTypes.Email, email) };

        var claimsIdentity = new List<ClaimsIdentity>
            { new(claims, CookieAuthenticationDefaults.AuthenticationScheme) };

        var principal = new ClaimsPrincipal(claimsIdentity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        AuthStatus = "Success";
        return Page();
    }
}