# ArpTools.psm1
#requires -version 7

if (-not ('ArpTools' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

public static class ArpTools
{
    [DllImport("Iphlpapi.dll", ExactSpelling = true)]
    public static extern int SendARP(
        uint DestIP,
        uint SrcIP,
        byte[] pMacAddr,
        ref uint PhyAddrLen
    );

    public static PhysicalAddress GetMac(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException("SendARP only supports IPv4 addresses");

        byte[] ipBytes = ip.GetAddressBytes();
        uint dest = (uint)ipBytes[0]
                  | ((uint)ipBytes[1] << 8)
                  | ((uint)ipBytes[2] << 16)
                  | ((uint)ipBytes[3] << 24);

        byte[] macAddr = new byte[6];
        uint macLen = (uint)macAddr.Length;

        int result = SendARP(dest, 0, macAddr, ref macLen);
        if (result != 0 || macLen == 0)
        {
            return null;
        }

        byte[] mac = new byte[macLen];
        Array.Copy(macAddr, mac, (int)macLen);

        try
        {
            return new PhysicalAddress(mac);
        }
        catch
        {
        }

        return null;
    }
}
'@
}
