using System;

namespace Aivpn.Ui.Services;

public static class ClientServiceFactory
{
    public static IClientService Create()
    {
        var backend = Environment.GetEnvironmentVariable("AIVPN_UI_BACKEND");
        if (string.Equals(backend, "process", StringComparison.OrdinalIgnoreCase))
        {
            return new ProcessClientService();
        }

        if (string.Equals(backend, "pipe", StringComparison.OrdinalIgnoreCase))
        {
            return new PipeClientService();
        }

        return new MockClientService();
    }
}
