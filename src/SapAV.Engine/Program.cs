using SapAV.Engine;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "SapAV Engine");
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
