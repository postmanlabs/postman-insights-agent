// SPDX-License-Identifier: Apache-2.0
//
// Combined ASP.NET Core test server: REST HTTPS (:8443) + gRPC-TLS (:8446).
// Capture path: postman-insights-agent DaemonSet → libssl uprobes (OpenSSL on Linux).

using System.Security.Cryptography.X509Certificates;
using Postman.Insights.Testdata.Services;

const string LogTimeFormat = "yyyy-MM-dd HH:mm:ss.fff";

var tlsDir = Environment.GetEnvironmentVariable("TLS_DIR") ?? "/tls";
var certPath = Path.Combine(tlsDir, "grpc-cert.pem");
var keyPath = Path.Combine(tlsDir, "grpc-key.pem");
var bind = Environment.GetEnvironmentVariable("BIND_HOST") ?? "0.0.0.0";
var httpsPort = int.Parse(Environment.GetEnvironmentVariable("HTTPS_PORT") ?? "8443");
var grpcPort = int.Parse(Environment.GetEnvironmentVariable("GRPC_PORT") ?? "8446");

if (!File.Exists(certPath) || !File.Exists(keyPath))
{
    throw new FileNotFoundException(
        $"missing TLS files under {tlsDir} (need grpc-cert.pem, grpc-key.pem)");
}

var serverCert = LoadServerCertificate(certPath, keyPath);

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options =>
{
    options.TimestampFormat = $"{LogTimeFormat} ";
    options.SingleLine = true;
});

// aspnet image sets ASPNETCORE_URLS=http://+:8080 by default; clear so only
// our Kestrel endpoints bind (avoids the port-8080 override warning).
builder.WebHost.UseSetting(WebHostDefaults.ServerUrlsKey, string.Empty);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(httpsPort, listen => listen.UseHttps(serverCert));
    options.ListenAnyIP(grpcPort, listen => listen.UseHttps(serverCert));
});

builder.Services.AddGrpc();

var externalHttpsBase = Environment.GetEnvironmentVariable("EXTERNAL_HTTPS_BASE")
    ?? "https://node-service:8443";

builder.Services.AddHttpClient("external", client =>
{
    client.BaseAddress = new Uri(externalHttpsBase.TrimEnd('/') + "/");
    client.Timeout = TimeSpan.FromSeconds(30);
}).ConfigurePrimaryHttpMessageHandler(() =>
{
    var handler = new HttpClientHandler();
    // Test harness: trust cluster self-signed certs (mounted CA or skip validation).
    handler.ServerCertificateCustomValidationCallback = static (_, _, _, _) => true;
    return handler;
});

var app = builder.Build();

app.MapGet("/phase5b2", () =>
    Results.Text("hello-from-dotnet-combined-server phase=5b2\n", "text/plain"));
app.MapGet("/", () =>
    Results.Text("hello-from-dotnet-combined-server phase=5b2\n", "text/plain"));

// Generic POST: accepts urlencoded or multipart form bodies (for HTTPS capture demos).
app.MapPost("/phase5b2", async (HttpRequest request, ILogger<Program> log) =>
{
    if (!request.HasFormContentType)
    {
        return Results.Text(
            "expected form body (application/x-www-form-urlencoded or multipart/form-data)\n",
            "text/plain",
            statusCode: StatusCodes.Status415UnsupportedMediaType);
    }

    var form = await request.ReadFormAsync();
    var lines = new List<string> { "ok POST /phase5b2" };
    foreach (var field in form)
    {
        foreach (var value in field.Value)
        {
            log.LogInformation("form field {Key}={Value}", field.Key, value);
            lines.Add($"{field.Key}={value}");
        }
    }

    lines.Add("");
    return Results.Text(string.Join("\n", lines), "text/plain");
});

// Outbound HTTPS GET to another in-cluster service (egress libssl capture).
app.MapGet("/phase5b2/call-external", async (
    IHttpClientFactory httpFactory,
    ILogger<Program> log,
    string? q) =>
{
    var query = string.IsNullOrEmpty(q) ? "demo" : q;
    var path = $"/phase5b2?from=dotnet&q={Uri.EscapeDataString(query)}&ts={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
    var http = httpFactory.CreateClient("external");
    log.LogInformation("outbound HTTPS GET {Base}{Path}", externalHttpsBase, path);

    using var response = await http.GetAsync(path);
    var body = await response.Content.ReadAsStringAsync();
    log.LogInformation(
        "outbound HTTPS response status={Status} body={Body}",
        (int)response.StatusCode,
        body.Trim());

    var lines = new List<string>
    {
        "ok outbound HTTPS GET",
        $"target={externalHttpsBase}{path}",
        $"status={(int)response.StatusCode}",
        body.TrimEnd(),
        "",
    };
    return Results.Text(string.Join("\n", lines), "text/plain");
});

app.MapGrpcService<GreeterService>();

var startupMsg =
    $"CombinedServer: HTTPS https://{bind}:{httpsPort}/phase5b2  +  gRPC https://{bind}:{grpcPort} (h2)" +
    $"  |  egress target {externalHttpsBase}";
Console.Error.WriteLine($"{DateTime.UtcNow.ToString(LogTimeFormat)}Z {startupMsg}");
app.Run();

static X509Certificate2 LoadServerCertificate(string certPath, string keyPath)
{
    var pemCert = X509Certificate2.CreateFromPemFile(certPath, keyPath);
    if (!pemCert.HasPrivateKey)
    {
        throw new InvalidOperationException(
            $"certificate at {certPath} has no private key (check {keyPath})");
    }

    // Kestrel on Linux needs a PKCS#12 export so the private key is bound for
    // server TLS (CreateFromPemFile alone can fail with NotSupportedException).
    return new X509Certificate2(pemCert.Export(X509ContentType.Pkcs12));
}
