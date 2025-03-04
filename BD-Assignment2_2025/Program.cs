using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddHttpClient();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHostedService<TemporaryBlockCleanupService>();

// In-memory storage
var blockedCountries = new ConcurrentDictionary<string, bool>();
var temporaryBlockedCountries = new ConcurrentDictionary<string, DateTime>();

// Register in DI container
builder.Services.AddSingleton(temporaryBlockedCountries);
builder.Services.AddHostedService<TemporaryBlockCleanupService>();


var blockedAttempts = new ConcurrentBag<dynamic>();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

// Utility method for country code validation
bool IsValidCountryCode(string code) => Regex.IsMatch(code, "^[A-Z]{2}$");

// POST: Block a country
app.MapPost("/api/countries/block", ([FromBody] string countryCode) =>
{
    if (string.IsNullOrWhiteSpace(countryCode) || !IsValidCountryCode(countryCode))
        return Results.BadRequest("Invalid country code. Must be a two-letter uppercase code.");
    if (blockedCountries.ContainsKey(countryCode))
        return Results.Conflict("Country already blocked.");
    blockedCountries[countryCode] = true;
    return Results.Ok("Country blocked successfully.");
});

// DELETE: Unblock a country
app.MapDelete("/api/countries/block/{countryCode}", (string countryCode) =>
{
    if (string.IsNullOrWhiteSpace(countryCode) || !IsValidCountryCode(countryCode))
        return Results.BadRequest("Invalid country code.");
    if (!blockedCountries.TryRemove(countryCode, out _))
        return Results.NotFound("Country not found.");
    return Results.Ok("Country unblocked successfully.");
});

// GET: List all blocked countries with pagination
app.MapGet("/api/countries/blocked", ([FromQuery] int page = 1, [FromQuery] int pageSize = 10) =>
{
    if (page < 1 || pageSize < 1)
        return Results.BadRequest("Page and pageSize must be greater than 0.");
    var pagedCountries = blockedCountries.Keys.Skip((page - 1) * pageSize).Take(pageSize);
    return Results.Ok(new { Page = page, PageSize = pageSize, TotalCount = blockedCountries.Count, Countries = pagedCountries });
});

// POST: Temporarily block a country
app.MapPost("/api/countries/temporal-block", ([FromBody] dynamic request) =>
{
    string countryCode = request.countryCode;
    int durationMinutes = request.durationMinutes;

    if (string.IsNullOrWhiteSpace(countryCode) || !IsValidCountryCode(countryCode))
        return Results.BadRequest("Invalid country code.");
    if (durationMinutes < 1 || durationMinutes > 1440)
        return Results.BadRequest("Duration must be between 1 and 1440 minutes (24 hours).");
    if (temporaryBlockedCountries.ContainsKey(countryCode))
        return Results.Conflict("Country is already temporarily blocked.");

    temporaryBlockedCountries[countryCode] = DateTime.UtcNow.AddMinutes(durationMinutes);
    return Results.Ok($"Country {countryCode} temporarily blocked for {durationMinutes} minutes.");
});

// GET: Find country by IP
app.MapGet("/api/ip/lookup", async (HttpContext context, [FromQuery] string? ipAddress, IHttpClientFactory httpClientFactory) =>
{
    ipAddress ??= context.Connection.RemoteIpAddress?.ToString();
    if (string.IsNullOrEmpty(ipAddress) || !Regex.IsMatch(ipAddress, @"^(\d{1,3}\.){3}\d{1,3}$"))
        return Results.BadRequest("Invalid or missing IP address.");

    var client = httpClientFactory.CreateClient();
    var response = await client.GetStringAsync($"https://ipapi.co/{ipAddress}/json/");
    var countryInfo = JsonSerializer.Deserialize<JsonElement>(response);
    return Results.Ok(countryInfo);
});

// GET: Check if IP is blocked
app.MapGet("/api/ip/check-block", async (HttpContext context, IHttpClientFactory httpClientFactory) =>
{
    var ipAddress = context.Connection.RemoteIpAddress?.ToString();
    if (string.IsNullOrEmpty(ipAddress)) return Results.BadRequest("Unable to determine IP.");

    var client = httpClientFactory.CreateClient();
    var response = await client.GetStringAsync($"https://ipapi.co/{ipAddress}/json/");
    var countryInfo = JsonSerializer.Deserialize<JsonElement>(response);
    var countryCode = countryInfo.GetProperty("country_code").GetString();

    if (string.IsNullOrEmpty(countryCode))
        return Results.BadRequest("Could not retrieve country information.");

    bool isBlocked = blockedCountries.ContainsKey(countryCode) || temporaryBlockedCountries.ContainsKey(countryCode);
    blockedAttempts.Add(new { ipAddress, Timestamp = DateTime.UtcNow, countryCode, Blocked = isBlocked, UserAgent = context.Request.Headers["User-Agent"].ToString() });

    return isBlocked ? Results.Forbid() : Results.Ok("Access granted.");
});

// GET: Fetch blocked attempts logs with pagination
app.MapGet("/api/logs/blocked-attempts", ([FromQuery] int page = 1, [FromQuery] int pageSize = 10) =>
{
    if (page < 1 || pageSize < 1)
        return Results.BadRequest("Page and pageSize must be greater than 0.");
    var pagedAttempts = blockedAttempts.Skip((page - 1) * pageSize).Take(pageSize);
    return Results.Ok(new { Page = page, PageSize = pageSize, TotalCount = blockedAttempts.Count, Attempts = pagedAttempts });
});

app.Run();

// Background service to clean up temporary blocked countries
class TemporaryBlockCleanupService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<TemporaryBlockCleanupService> _logger;

    public TemporaryBlockCleanupService(IServiceProvider serviceProvider, ILogger<TemporaryBlockCleanupService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var temporaryBlockedCountries = scope.ServiceProvider.GetRequiredService<ConcurrentDictionary<string, DateTime>>();

                var now = DateTime.UtcNow;
                var expiredCountries = temporaryBlockedCountries
                    .Where(kvp => kvp.Value <= now)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var country in expiredCountries)
                {
                    temporaryBlockedCountries.TryRemove(country, out _);
                    _logger.LogInformation($"Unblocked country: {country} at {DateTime.UtcNow}");
                }
            }

            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }
}

