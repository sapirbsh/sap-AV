using Microsoft.Extensions.Options;
using SapAV.Core.Processes;

namespace SapAV.Engine.Processes;

/// <summary>
/// Starts the process event source (E8) with the engine and stops it at shutdown. It starts only in the Windows service (or a
/// console run with <see cref="ProcessEventSourceOptions.StartInConsole"/>), so tests and CI, which build and start hosts
/// elevated, never create a kernel trace session. A failed start is logged and reported in the source's status; the
/// engine keeps running.
/// </summary>
public sealed class ProcessEventSourceService : IHostedService
{
    private readonly IProcessEventSource _source;
    private readonly ProcessEventSourceOptions _options;
    private readonly ILogger<ProcessEventSourceService> _logger;
    private readonly Func<bool> _isService;
    private bool _started;

    public ProcessEventSourceService(IProcessEventSource source, IOptions<ProcessEventSourceOptions> options, ILogger<ProcessEventSourceService> logger)
        : this(source, options.Value, logger, EngineAccount.IsWindowsService)
    {
    }

    internal ProcessEventSourceService(IProcessEventSource source, ProcessEventSourceOptions options, ILogger<ProcessEventSourceService> logger,
        Func<bool> isService)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _isService = isService ?? throw new ArgumentNullException(nameof(isService));
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("Process event source disabled ({Section}:Enabled = false)", ProcessEventSourceOptions.SectionName);
            return;
        }

        if (!_options.StartInConsole && !_isService())
        {
            _logger.LogInformation("Process event source not started in a console run (set {Section}:StartInConsole = true to debug it)",
                ProcessEventSourceOptions.SectionName);
            return;
        }

        try
        {
            _started = true;
            var status = await _source.StartAsync(cancellationToken).ConfigureAwait(false);
            if (!status.IsReceiving)
            {
                _logger.LogWarning("Process event source is {Health}: {Detail}", status.Health, status.Detail);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
        {
            _logger.LogError(ex, "Process event source failed to start");
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_started)
        {
            await _source.StopAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
