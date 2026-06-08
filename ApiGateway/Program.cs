using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

// --- Forwarded headers (must be configured before the pipeline is built) ---
// Clears the default localhost-only allowlist so the gateway trusts X-Forwarded-For
// from the ingress. Only safe when the gateway is not directly internet-facing.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// --- Startup validation ---

var authority = builder.Configuration["Auth:Authority"];
if (string.IsNullOrEmpty(authority))
    throw new InvalidOperationException(
        "Auth:Authority must be configured. Use environment variable Auth__Authority in production.");

var issuer = builder.Configuration["Auth:Issuer"];
var audience = builder.Configuration["Auth:Audience"];

var allowedOrigins = builder.Configuration
    .GetSection("Cors:AllowedOrigins")
    .Get<string[]>() ?? [];

if (allowedOrigins.Length == 0 && !builder.Environment.IsDevelopment())
    throw new InvalidOperationException(
        "Cors:AllowedOrigins must be configured in production. Use Cors__AllowedOrigins__0=https://yourapp.com");

// --- YARP ---

builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(ctx =>
    {
        ctx.AddRequestTransform(transformCtx =>
        {
            // Strip client-provided identity headers on every route (prevents impersonation)
            transformCtx.ProxyRequest.Headers.Remove("X-User-Id");
            transformCtx.ProxyRequest.Headers.Remove("X-User-Email");

            // Propagate correlation ID to all downstream services
            if (transformCtx.HttpContext.Items.TryGetValue("CorrelationId", out var corrId))
                transformCtx.ProxyRequest.Headers.TryAddWithoutValidation("X-Correlation-ID", corrId?.ToString());

            return ValueTask.CompletedTask;
        });

        // Re-inject verified identity only on protected routes
        if (ctx.Route.AuthorizationPolicy is not null)
        {
            ctx.AddRequestTransform(transformCtx =>
            {
                var user = transformCtx.HttpContext.User;
                if (user.Identity?.IsAuthenticated != true)
                    return ValueTask.CompletedTask;

                var userId = user.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? user.FindFirstValue("sub");
                var userEmail = user.FindFirstValue(ClaimTypes.Email)
                    ?? user.FindFirstValue("email");

                if (userId is not null)
                    transformCtx.ProxyRequest.Headers.Add("X-User-Id", userId);
                if (userEmail is not null)
                    transformCtx.ProxyRequest.Headers.Add("X-User-Email", userEmail);

                return ValueTask.CompletedTask;
            });
        }
    });

// --- JWT ---

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
        };
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    });

builder.Services.AddAuthorization();

// --- CORS ---

builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy =>
        policy
            .WithOrigins(allowedOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials()));

// --- Rate limiting (per IP, fixed window) ---

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                Window = TimeSpan.FromMinutes(1),
                PermitLimit = 300,
                QueueLimit = 0,
            }));
});

// --- Health checks ---

builder.Services.AddHttpClient();
builder.Services.AddSingleton(new AuthServiceHealthCheck.Options(authority));
builder.Services.AddHealthChecks()
    .AddCheck<AuthServiceHealthCheck>("authservice", tags: ["ready"]);

// --- Build ---

var app = builder.Build();

// Must be absolute first — rewrites RemoteIpAddress from X-Forwarded-For
// before rate limiting and logging read it
app.UseForwardedHeaders();

// Must be first so unhandled exceptions never leak stack traces
app.UseExceptionHandler(errApp =>
    errApp.Run(async ctx =>
    {
        ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsJsonAsync(new { error = "An unexpected error occurred." });
    }));

if (!app.Environment.IsDevelopment())
    app.UseHsts();

app.UseHttpsRedirection();
app.UseCors();

app.Use(async (context, next) =>
{
    // Security headers
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");

    // Correlation ID: accept from client or generate new one
    const string correlationHeader = "X-Correlation-ID";
    if (!context.Request.Headers.TryGetValue(correlationHeader, out var correlationId)
        || string.IsNullOrWhiteSpace(correlationId))
        correlationId = Guid.NewGuid().ToString();

    context.Items["CorrelationId"] = correlationId.ToString();
    context.Response.Headers.Append(correlationHeader, correlationId.ToString());

    await next();
});

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// Liveness: is the gateway process alive?
app.MapHealthChecks("/health").AllowAnonymous();

// Readiness: can the gateway reach AuthService?
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
}).AllowAnonymous();

app.MapReverseProxy();

app.Run();

// Checks that AuthService's JWKS endpoint is reachable
public class AuthServiceHealthCheck : IHealthCheck
{
    public record Options(string Authority);

    private readonly IHttpClientFactory _factory;
    private readonly string _jwksUrl;

    public AuthServiceHealthCheck(IHttpClientFactory factory, Options opts)
    {
        _factory = factory;
        _jwksUrl = $"{opts.Authority.TrimEnd('/')}/.well-known/jwks.json";
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var client = _factory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(5);
            var response = await client.GetAsync(_jwksUrl, cancellationToken);
            return response.IsSuccessStatusCode
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Degraded($"AuthService returned {(int)response.StatusCode}");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy(ex.Message);
        }
    }
}
