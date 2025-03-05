using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.Linq;
using Microsoft.Extensions.Configuration;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Net;

[Route("api/countries")]
[ApiController]
public class CountryController : ControllerBase
{

    // Using ConcurrentDictionary for thread safety
    private static readonly ConcurrentDictionary<string, bool> blockedCountries = new();

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _apiBaseUrl;
    private readonly string _apiKey;
    private static readonly ConcurrentDictionary<string, DateTime> temporaryBlockedCountries = new();
    private readonly ILogger<CountryController> _logger;
    private static readonly ConcurrentBag<object> blockedAttempts = new();

    public CountryController(IHttpClientFactory httpClientFactory, IConfiguration configuration, ILogger<CountryController> logger)
    {
        _httpClientFactory = httpClientFactory;
        _apiBaseUrl = configuration["ThirdPartyAPI:BaseUrl"];
        _apiKey = configuration["ThirdPartyAPI:ApiKey"];
        _logger = logger;
        StartCleanupTask();
    }

    /// <summary>
    /// Blocks a country by its country code.
    /// </summary>
    [HttpPost("block")]
    public IActionResult BlockCountry([FromBody] string countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode) || !IsValidCountryCode(countryCode))
            return BadRequest("Invalid country code. Must be a two-letter uppercase code.");

        if (!blockedCountries.TryAdd(countryCode, true))
            return Conflict("Country already blocked.");

        return Ok("Country blocked successfully.");
    }

    /// <summary>
    /// Unblocks a country by its country code.
    /// </summary>
    [HttpDelete("block/{countryCode}")]
    public IActionResult UnblockCountry(string countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode) || !IsValidCountryCode(countryCode))
            return BadRequest("Invalid country code.");

        if (!blockedCountries.TryRemove(countryCode, out _))
            return NotFound("Country not found.");

        return Ok("Country unblocked successfully.");
    }

    /// <summary>
    /// Gets a paginated list of blocked countries.
    /// </summary>
    [HttpGet("blocked")]
    public IActionResult GetBlockedCountries([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        if (page < 1 || pageSize < 1)
            return BadRequest("Page and pageSize must be greater than 0.");

        var pagedCountries = blockedCountries.Keys.Skip((page - 1) * pageSize).Take(pageSize);
        return Ok(new
        {
            Page = page,
            PageSize = pageSize,
            TotalCount = blockedCountries.Count,
            Countries = pagedCountries
        });

    }

    [HttpGet("lookup")]
    public async Task<IActionResult> GetCountryByIp([FromQuery] string? ipAddress)
    {
        // Get the caller's IP if no IP is provided
        ipAddress ??= HttpContext.Connection.RemoteIpAddress?.ToString();

        // Validate IP Address
        if (string.IsNullOrWhiteSpace(ipAddress) || !IsValidIp(ipAddress))
            return BadRequest("❌ Invalid or missing IP address.");

        // Call the third-party API
        var client = _httpClientFactory.CreateClient();
        var requestUrl = $"{_apiBaseUrl}?apiKey={_apiKey}&ip={ipAddress}";
        var response = await client.GetStringAsync(requestUrl);
        var countryInfo = JsonSerializer.Deserialize<JsonElement>(response);

        return Ok(countryInfo);
    }
    /// <summary>
    /// Temporarily blocks a country for a specified duration (1 to 1440 minutes).
    /// </summary>
    [HttpPost("temporal-block")]
    public IActionResult TemporarilyBlockCountry([FromBody] TemporaryBlockRequest request)
    {
        if (request == null)
            return BadRequest("Invalid request.");

        string countryCode = request.CountryCode;
        int durationMinutes = request.DurationMinutes;

        if (string.IsNullOrWhiteSpace(countryCode) || !IsValidCountryCode(countryCode))
            return BadRequest("Invalid country code.");
        if (durationMinutes < 1 || durationMinutes > 1440)
            return BadRequest("Duration must be between 1 and 1440 minutes (24 hours).");
        if (temporaryBlockedCountries.ContainsKey(countryCode))
            return Conflict("Country is already temporarily blocked.");

        temporaryBlockedCountries[countryCode] = DateTime.UtcNow.AddMinutes(durationMinutes);
        return Ok($"Country {countryCode} temporarily blocked for {durationMinutes} minutes.");
    }


    /// <summary>
    /// Unblocks a temporarily blocked country manually.
    /// </summary>
    [HttpDelete("temporal-block/{countryCode}")]
    public IActionResult UnblockTemporarilyBlockedCountry(string countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode) || !IsValidCountryCode(countryCode))
            return BadRequest("Invalid country code.");

        if (!temporaryBlockedCountries.TryRemove(countryCode, out _))
            return NotFound("Country was not temporarily blocked.");

        return Ok($"Country {countryCode} has been manually unblocked.");
    }

    /// <summary>
    /// Retrieves a list of all temporarily blocked countries.
    /// </summary>
    [HttpGet("temporal-blocked")]
    public IActionResult GetTemporarilyBlockedCountries()
    {
        var blockedList = temporaryBlockedCountries
            .Select(kvp => new { CountryCode = kvp.Key, UnblockTime = kvp.Value })
            .ToList();

        return Ok(blockedList);
    }

    [HttpGet("ip/check-block")]
    public async Task<IActionResult> CheckIpBlock()
    {
        // Get the client's IP address
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (string.IsNullOrEmpty(ipAddress))
        {
            return BadRequest("Unable to determine IP.");
        }

        var client = _httpClientFactory.CreateClient();
        var requestUrl = $"{_apiBaseUrl}?apiKey={_apiKey}&ip={ipAddress}";

        try
        {
            var response = await client.GetAsync(requestUrl);

            if (response.StatusCode == HttpStatusCode.Locked) // 423 Locked
            {
                _logger.LogWarning("IP check blocked: {IP}. API responded with 423 Locked.", ipAddress);
                return StatusCode(423, "API temporarily locked. Please try again later.");
            }

            response.EnsureSuccessStatusCode();
            var responseBody = await response.Content.ReadAsStringAsync();
            var countryInfo = JsonSerializer.Deserialize<JsonElement>(responseBody);

            if (!countryInfo.TryGetProperty("country_code2", out var countryCodeElement))
            {
                return BadRequest("Could not retrieve country information.");
            }

            var countryCode = countryCodeElement.GetString();

            bool isBlocked = blockedCountries.ContainsKey(countryCode) || temporaryBlockedCountries.ContainsKey(countryCode);

            // Log the attempt
            blockedAttempts.Add(new { ipAddress, Timestamp = DateTime.UtcNow, countryCode, isBlocked });
            _logger.LogInformation("IP check attempt: {IP}, Country: {Country}, Blocked: {Blocked}", ipAddress, countryCode, isBlocked);

            return isBlocked ? Forbid("Access denied: Your country is restricted.") : Ok(new { Message = "Access granted.", CountryCode = countryCode, IP = ipAddress });
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Error checking IP block for {IP}", ipAddress);
            return StatusCode(500, "Failed to retrieve IP information. Please try again later.");
        }
    }



    /// <summary>
    /// Background task to remove expired temporary blocks.
    /// </summary>
    /// 
    public class TemporaryBlockRequest
    {
        public string CountryCode { get; set; }
        public int DurationMinutes { get; set; }
    }
    private void StartCleanupTask()
    {
        Task.Run(async () =>
        {
            while (true)
            {
                await Task.Delay(TimeSpan.FromMinutes(6));
                var now = DateTime.UtcNow;

                var expiredCountries = temporaryBlockedCountries
                    .Where(kvp => kvp.Value <= now)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var country in expiredCountries)
                {
                    temporaryBlockedCountries.TryRemove(country, out _);
                    _logger.LogInformation($"✅ Unblocked country: {country} at {DateTime.UtcNow}");
                }
            }
        });
    }

    private static bool IsValidIp(string ipAddress)
    {
        var ipv4Pattern = @"^(?:\d{1,3}\.){3}\d{1,3}$";
        var ipv6Pattern = @"^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$";
        return Regex.IsMatch(ipAddress, ipv4Pattern) || Regex.IsMatch(ipAddress, ipv6Pattern);
    }

    /// <summary>
    /// Helper method to validate country codes.
    /// </summary>
    private bool IsValidCountryCode(string countryCode)
    {
        return countryCode.Length == 2 && countryCode.ToUpper() == countryCode;
    }
    public class TemporaryBlockCleanupService : BackgroundService
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
                        _logger.LogInformation($"✅ Unblocked country: {country} at {DateTime.UtcNow}");
                    }
                }

                await Task.Delay(TimeSpan.FromMinutes(6), stoppingToken);
            }
        }
    }
}