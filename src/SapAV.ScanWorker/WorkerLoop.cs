using System.Buffers.Binary;
using System.Text;
using SapAV.Core.Scanning.Isolation;

namespace SapAV.ScanWorker;

/// <summary>Reads framed requests, hands them to <see cref="WorkerService"/>, writes framed responses. One at a time.</summary>
internal sealed class WorkerLoop(WorkerService service, Stream input, Stream output)
{
    /// <summary>0 when the broker closed the request pipe; 3 on a protocol violation by the broker.</summary>
    public async Task<int> RunAsync()
    {
        while (true)
        {
            WorkerRequest request;
            try
            {
                var frame = WorkerFraming.Read(input, WorkerLimits.MaxRulesRequestBytes);
                if (frame is null)
                {
                    return 0;
                }

                request = WorkerJson.Deserialize<WorkerRequest>(frame);
            }
            catch (WorkerProtocolException)
            {
                return 3;
            }
            catch (IOException)
            {
                return 0; // the broker went away
            }

            var fault = request.Scan?.TestFault ?? WorkerTestFault.None;
            if (fault != WorkerTestFault.None && service.TestHooksEnabled && TryWriteFaultyResponse(request, fault))
            {
                continue;
            }

            var response = await service.HandleAsync(request).ConfigureAwait(false);
            byte[] bytes;
            try
            {
                bytes = WorkerJson.Serialize(response, WorkerLimits.MaxResponseBytes);
            }
            catch (WorkerProtocolException ex)
            {
                bytes = WorkerJson.Serialize(WorkerService.Failed(request.Id, ex.Message), WorkerLimits.MaxResponseBytes);
            }

            try
            {
                WorkerFraming.Write(output, bytes, WorkerLimits.MaxResponseBytes);
            }
            catch (IOException)
            {
                return 0;
            }
        }
    }

    /// <summary>Test hooks only: answers with a deliberately broken response. False for faults handled by the service.</summary>
    private bool TryWriteFaultyResponse(WorkerRequest request, WorkerTestFault fault)
    {
        switch (fault)
        {
            case WorkerTestFault.MalformedResponse:
                WorkerFraming.Write(output, "{ this is not json"u8, WorkerLimits.MaxResponseBytes);
                return true;

            case WorkerTestFault.WrongSchemaResponse:
                WorkerFraming.Write(output, Encoding.UTF8.GetBytes(
                    $$"""{"Id":{{request.Id}},"Kind":"Scanned","Rules":null,"Report":{"Verdict":"Clean"},"Probe":null,"Error":null}"""),
                    WorkerLimits.MaxResponseBytes);
                return true;

            case WorkerTestFault.WrongIdResponse:
                var wrong = WorkerService.Failed(request.Id + 1, "a response for another request");
                WorkerFraming.Write(output, WorkerJson.Serialize(wrong, WorkerLimits.MaxResponseBytes), WorkerLimits.MaxResponseBytes);
                return true;

            case WorkerTestFault.OversizedResponse:
                // A header announcing more than the cap; the broker must reject it before reading the body.
                Span<byte> header = stackalloc byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(header, WorkerLimits.MaxResponseBytes + 1);
                output.Write(header);
                output.Write(new byte[64 * 1024]);
                output.Flush();
                return true;

            default:
                return false;
        }
    }
}
