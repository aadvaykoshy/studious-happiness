using System;
using System.Runtime.InteropServices;
using System.Text;
namespace VncHelper {
public static class VncPassHelper {
    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    static extern int BCryptOpenAlgorithmProvider(out IntPtr h, string alg, string impl, uint flags);
    [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)]
    static extern int BCryptSetProperty(IntPtr obj, string prop, byte[] val, int cbVal, uint flags);
    [DllImport("bcrypt.dll")]
    static extern int BCryptGenerateSymmetricKey(IntPtr hAlg, out IntPtr hKey, IntPtr keyObj, int cbKeyObj, byte[] secret, int cbSecret, uint flags);
    [DllImport("bcrypt.dll")]
    static extern int BCryptEncrypt(IntPtr hKey, byte[] input, int cbInput, IntPtr paddingInfo, byte[] iv, int cbIV, byte[] output, int cbOutput, out int cbResult, uint flags);
    [DllImport("bcrypt.dll")]
    static extern int BCryptDestroyKey(IntPtr hKey);
    [DllImport("bcrypt.dll")]
    static extern int BCryptCloseAlgorithmProvider(IntPtr h, uint flags);
    static void Check(int status, string op) {
        if (status != 0)
            throw new Exception(string.Format("{0} failed with NTSTATUS 0x{1:X8}", op, (uint)status));
    }
    public static byte[] Hash(byte[] key) {
        IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero;
        try {
            Check(BCryptOpenAlgorithmProvider(out hAlg, "DES", null, 0), "BCryptOpenAlgorithmProvider");
            byte[] ecb = Encoding.Unicode.GetBytes("ECB\0");
            Check(BCryptSetProperty(hAlg, "ChainingMode", ecb, ecb.Length, 0), "BCryptSetProperty");
            Check(BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0), "BCryptGenerateSymmetricKey");
            byte[] plain = new byte[8];
            byte[] cipher = new byte[8];
            int cb;
            Check(BCryptEncrypt(hKey, plain, 8, IntPtr.Zero, null, 0, cipher, 8, out cb, 0), "BCryptEncrypt");
            return cipher;
        } finally {
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }
}
}
