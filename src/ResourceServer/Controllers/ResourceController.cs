using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ResourceServer.Controllers;

[ApiController]
[Route("resources")]
public class ResourceController : Controller
{
    [Authorize]
    [HttpGet]
    public async Task<IActionResult> GetResource()
    {
        var user = HttpContext.User?.Identity?.Name;
        return Ok($"user: {user}");
    }
}