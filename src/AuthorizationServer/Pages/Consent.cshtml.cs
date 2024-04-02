using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace AuthorizationServer.Pages;

public class Consent : PageModel
{
    public string? ReturnUrl { get; set; }
    
    public IActionResult OnGet(string returnUrl)
    {
        ReturnUrl = returnUrl;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string grant)
    {
        User.SetClaim(Constants.ConsentNaming, grant);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, User);

        return Redirect(ReturnUrl!);
    }
}