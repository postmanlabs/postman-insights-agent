// SPDX-License-Identifier: Apache-2.0

using Grpc.Core;
using Phase5c2;

namespace Postman.Insights.Testdata.Services;

public sealed class GreeterService : Greeter.GreeterBase
{
    public override Task<HelloReply> SayHello(HelloRequest request, ServerCallContext context)
    {
        var name = string.IsNullOrWhiteSpace(request.Name) ? "world" : request.Name;
        return Task.FromResult(new HelloReply
        {
            Message = $"hi {name} from-dotnet-combined-server",
        });
    }
}
