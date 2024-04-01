var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("Postgres");

builder.Services.AddControllers();
builder.Services.AddRazorPages();

var app = builder.Build();

app.MapControllers();
app.MapRazorPages();

app.Run();
