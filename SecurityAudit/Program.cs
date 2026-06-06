using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SecurityAudit.Database;
using SecurityAudit.Domain;
using SecurityAudit.Requests;
using SecurityAudit.Storage;
using System.ComponentModel.DataAnnotations;

var builder = WebApplication.CreateBuilder(args);

var apiKey = builder.Configuration["ApiKey"]
    ?? throw new InvalidOperationException("Brak ApiKey w konfiguracji!");

builder.Services.AddRateLimiter(opt =>
{
    opt.AddFixedWindowLimiter("api", o =>
    {
        o.PermitLimit = 5;
        o.Window = TimeSpan.FromSeconds(10);
        o.QueueLimit = 0;
    });
});

builder.Services.AddDbContext<AppDbContext>(opt => opt.UseInMemoryDatabase("AuditDb"));

var app = builder.Build();

app.UseRateLimiter();

app.MapPost("/audits", async (CreateAuditRequest req, AppDbContext db) =>
{
    var results = new List<ValidationResult>();
    var ctx = new ValidationContext(req);

    if (!Validator.TryValidateObject(req, ctx, results, true))
    {
        var errors = results.ToDictionary(
            r => r.MemberNames.First(),
            r => new[] { r.ErrorMessage! });

        return Results.ValidationProblem(errors);
    }

    var item = new AuditItem
    {
        Title = req.Title,
        Priority = req.Priority,
        Description = req.Description
    };

    db.Audits.Add(item);
    await db.SaveChangesAsync();

    return Results.Created($"/audits/{item.Id}", item);
});

app.MapGet("/tokens/save", (string rawToken) =>
{
    SecureTokenStorage.Save(rawToken);
    return Results.Ok("Token został bezpiecznie zaszyfrowany i zapisany na dysku przez DPAPI.");
});

app.MapGet("/tokens/load", () =>
{
    try
    {
        string token = SecureTokenStorage.Load();
        return Results.Ok(new { Preview = $"{token[..4]}***" });
    }
    catch (FileNotFoundException)
    {
        return Results.NotFound("Nie znaleziono pliku tokenu.");
    }
});

app.MapGet("/xss-test", () =>
{
    string userInput = "<script>alert('Atak XSS!');</script>Witaj <b style='color:red;'>Jakub</b>";

    string bezpieczne = System.Web.HttpUtility.HtmlEncode(userInput);
    string niebezpieczne = userInput;
    string sanityzowane = new Ganss.Xss.HtmlSanitizer().Sanitize(userInput);

    return Results.Content($$"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Ćwiczenie 6.2 - XSS</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" />
    </head>
    <body class="container py-4" style="font-family: sans-serif;">
        <h3 class="mb-4">Ćwiczenie 6.2: XSS i zabezpieczenia (Symulacja Blazora)</h3>
        
        <div class="card my-3 border-success">
            <div class="card-header bg-success text-white"><strong>1. Bezpieczne: Blazor automatycznie enkoduje HTML</strong></div>
            <div class="card-body"><p>{{bezpieczne}}</p></div>
        </div>

        <div class="card my-3 border-danger">
            <div class="card-header bg-danger text-white"><strong>2. NIEBEZPIECZNE: renderuje surowy HTML z niezaufanego zrodla</strong></div>
            <div class="card-body"><p>{{niebezpieczne}}</p></div>
        </div>

        <div class="card my-3 border-info">
            <div class="card-header bg-info text-white"><strong>3. Jesli HTML jest potrzebny --- najpierw sanityzuj</strong></div>
            <div class="card-body"><p>{{sanityzowane}}</p></div>
        </div>
    </body>
    </html>
    """, "text/html");
});

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

    db.Users.Add(new User { Username = "Jakub" });
    await db.SaveChangesAsync();

    var malicious = "' OR 1=1 --";
    var result = await GetUserSecureAsync(malicious, db);
    Console.WriteLine($"Wynik testu SQLi: {(result == null ? "BEZPIECZNIE (result jest null)" : "WYCIEK DANYCH!")}");

    var bad = new CreateAuditRequest
    {
        Title = "<script>alert('xss')</script>",
        Priority = 99
    };
    var vResults = new List<ValidationResult>();
    bool valid = Validator.TryValidateObject(bad, new ValidationContext(bad), vResults, true);

    Console.WriteLine($"Walidacja: {(valid ? "OK" : "BLAD")}");
    foreach (var v in vResults)
        Console.WriteLine($" - {v.ErrorMessage}");
}

static async Task<User?> GetUserSecureAsync(string username, AppDbContext db)
{
    return await db.Users.FirstOrDefaultAsync(u => u.Username == username);
}

app.Run();