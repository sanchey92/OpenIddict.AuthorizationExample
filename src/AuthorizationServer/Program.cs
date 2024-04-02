using AuthorizationServer.Services;

var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("Postgres");

builder.Services.AddControllers();
builder.Services.AddRazorPages();

builder.Services.AddTransient<IAuthorizationService, AuthorizationService>();

var app = builder.Build();

app.MapControllers();
app.MapRazorPages();

app.Run();
