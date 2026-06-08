using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

public static class ArpTools
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(
        uint destIp,
        uint srcIp,
        byte[] pMacAddr,
        ref uint phyAddrLen);

    public static async Task<IPAddress?> FindByMacAsync(
        IPAddress start,
        IPAddress end,
        PhysicalAddress targetMac,
        int maxConcurrency,
        TimeSpan interProbeDelay,
        CancellationToken externalCt = default)
    {
        if (start.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            end.AddressFamily   != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 supported for ARP.");

        uint startUInt = ToOrderedUInt32(start);
        uint endUInt   = ToOrderedUInt32(end);
        if (endUInt < startUInt)
            throw new ArgumentException("End IP must be >= start IP.");

        // Internal CTS linked to the external one (Ctrl-C will cancel externalCt)
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        var ct = cts.Token;

        using var semaphore = new SemaphoreSlim(maxConcurrency);

        var targetBytes = targetMac.GetAddressBytes();
        IPAddress? foundIp = null;
        object lockObj = new();

        // Log immediately when the external token (PipelineStopToken) is cancelled
        using var externalCancelRegistration = externalCt.CanBeCanceled
            ? externalCt.Register(() =>
            {
                Console.WriteLine("Cancelling...");
            })
            : default;

        // Signal when all tasks have completed
        var tcs = new TaskCompletionSource<object?>();
        int remaining = 0;

        for (uint addr = startUInt; addr <= endUInt; addr++)
        {
            var ip = FromOrderedUInt32(addr);

            //If pipeline token is cancelled due to Ctrl-C, stop queuing new work.
            if (externalCt.IsCancellationRequested) {
                Console.WriteLine($"...stopped somewhere before {ip}");
                break;
            }

            //If pipeline token is cancelled due to success, stop queuing new work.
            //(Can't check this earlier, because this ct will also fire under ctrl-c.)
            if(ct.IsCancellationRequested)
                break;

            int index = (int)(addr - startUInt);
            //Print at intervals that double.
            if (((index+1) & index) == 0)
            {
                Console.WriteLine($"Scanning {ip} ...");
            }

            await semaphore.WaitAsync().ConfigureAwait(false);

            // We are about to start a task -> count it
            Interlocked.Increment(ref remaining);

            _ = Task.Run(async () =>
            {
                try
                {
                    if (!ct.IsCancellationRequested)
                    {
                        PhysicalAddress? mac = TrySendArp(ip);
                        if (mac is not null && MacEquals(mac, targetBytes))
                        {
                            lock (lockObj)
                            {
                                if (foundIp == null)
                                    foundIp = ip;
                            }
                            cts.Cancel(); // internal “found it” cancel
                        }
                    }
                }
                finally
                {
                    semaphore.Release();

                    if (interProbeDelay > TimeSpan.Zero && !ct.IsCancellationRequested)
                        await Task.Delay(interProbeDelay).ConfigureAwait(false);

                    // One more task finished
                    if (Interlocked.Decrement(ref remaining) == 0)
                        tcs.TrySetResult(null);
                }
            });
        }

        // If we never started any tasks (e.g. Ctrl-C before loop / very early), complete tcs
        if (remaining == 0)
            tcs.TrySetResult(null);

        // Wait for all started tasks to finish
        await tcs.Task.ConfigureAwait(false);

        return foundIp;
    }

    public static PhysicalAddress? TrySendArp(IPAddress ip, IPAddress? srcIp = null)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return null;

        uint dest = BitConverter.ToUInt32(ip.GetAddressBytes(), 0);      // network bytes, no reverse
        uint src  = srcIp is null ? 0 : BitConverter.ToUInt32(srcIp.GetAddressBytes(), 0);

        byte[] macBytes = new byte[6];
        uint macLen = (uint)macBytes.Length;

        int result = SendARP(dest, src, macBytes, ref macLen);

        // 0 = NO_ERROR
        if (result != 0 || macLen == 0)
            return null;

        if (macLen != 6)
        {
            var trimmed = new byte[macLen];
            Array.Copy(macBytes, trimmed, macLen);
            macBytes = trimmed;
        }

        return new PhysicalAddress(macBytes);
    }

    private static bool MacEquals(PhysicalAddress mac, byte[] targetBytes)
    {
        var bytes = mac.GetAddressBytes();
        if (bytes.Length != targetBytes.Length) return false;
        for (int i = 0; i < bytes.Length; i++)
            if (bytes[i] != targetBytes[i]) return false;
        return true;
    }

    private static uint ToUInt32(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes(); // network order (big-endian)
        if (bytes.Length != 4)
            throw new ArgumentException("Only IPv4 supported.", nameof(ip));

        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);

        return BitConverter.ToUInt32(bytes, 0);
    }

    private static IPAddress FromUInt32(uint value)
    {
        var bytes = BitConverter.GetBytes(value); // little-endian on most machines
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);

        return new IPAddress(bytes); // expects network order
    }

    // For range math (monotonic increasing uint)
    private static uint ToOrderedUInt32(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes(); // network order
        if (bytes.Length != 4)
            throw new ArgumentException("Only IPv4 supported.", nameof(ip));

        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);

        return BitConverter.ToUInt32(bytes, 0);
    }

    private static IPAddress FromOrderedUInt32(uint value)
    {
        var bytes = BitConverter.GetBytes(value); // little-endian
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return new IPAddress(bytes); // network order
    }

}
