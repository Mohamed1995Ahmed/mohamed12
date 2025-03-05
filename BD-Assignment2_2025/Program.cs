using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

var builder = WebApplication.CreateBuilder(args);

// Load Configuration
var config = builder.Configuration;
var apiBaseUrl = config["ThirdPartyAPI:BaseUrl"];
var apiKey = config["ThirdPartyAPI:ApiKey"];

// Add services
builder.Services.AddHttpClient();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<ConcurrentDictionary<string, DateTime>>();


var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

// In-memory storage for blocked countries
var blockedCountries = new ConcurrentDictionary<string, bool>();
var temporaryBlockedCountries = app.Services.GetRequiredService<ConcurrentDictionary<string, DateTime>>();
var blockedAttempts = new ConcurrentBag<dynamic>();

// Utility method for country code validation
bool IsValidCountryCode(string code) => Regex.IsMatch(code, "^[A-Z]{2}$");

// POST: Block a country


// DELETE: Unblock a country


// GET: List all blocked countries with pagination


// POST: Temporarily block a country


// GET: Find country by IP


// GET: Check if IP is blocked


app.Run();

// Background service to clean up temporary blocked countries

    

