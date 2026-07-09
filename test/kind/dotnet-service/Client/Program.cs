// SPDX-License-Identifier: Apache-2.0
//
// Minimal client: HTTPS GET /phase5b2 + gRPC SayHello (TLS).
// Usage:
//   TLS_DIR=test/kind/certs dotnet run --project test/kind/dotnet-service/Client
//   dotnet run -- https://127.0.0.1

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Grpc.Net.Client;
using Phase5c2;

var host = args.Length > 0 ? args[0].TrimEnd('/') : "https://127.0.0.1";
var tlsDir = Environment.GetEnvironmentVariable("TLS_DIR") ?? "/tls";
var trustPem = Path.Combine(tlsDir, "hello-https-trust.pem");
if (!File.Exists(trustPem))
{
    trustPem = Path.Combine(tlsDir, "grpc-cert.pem");
}

var httpsPort = int.Parse(Environment.GetEnvironmentVariable("HTTPS_PORT") ?? "8443");
var grpcPort = int.Parse(Environment.GetEnvironmentVariable("GRPC_PORT") ?? "8446");
var grpcCount = args.Length > 1 ? int.Parse(args[1]) : 2;

var handler = new HttpClientHandler();
// In-pod / test harness: trust the mounted self-signed CA (or skip validation).
handler.ServerCertificateCustomValidationCallback = static (_, _, _, _) => true;

var httpsUri = new Uri($"{host}:{httpsPort}/phase5b2");
using (var http = new HttpClient(handler, disposeHandler: false))
{
    var body = await http.GetStringAsync(httpsUri);
    Console.Error.WriteLine($"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}Z HTTPS GET {httpsUri} → {body.Trim()}");
}

using var channel = GrpcChannel.ForAddress($"{host}:{grpcPort}", new GrpcChannelOptions
{
    HttpHandler = handler,
    DisposeHttpClient = true,
});
var stub = new Greeter.GreeterClient(channel);
for (var i = 0; i < grpcCount; i++)
{
    var reply = await stub.SayHelloAsync(new HelloRequest { Name = $"dotnet-client-{i}" });
    Console.Error.WriteLine($"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}Z gRPC SayHello → {reply.Message}");
}
