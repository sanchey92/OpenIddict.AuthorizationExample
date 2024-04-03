using Microsoft.EntityFrameworkCore;

namespace AuthorizationServer;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : DbContext(options)
{
    
}