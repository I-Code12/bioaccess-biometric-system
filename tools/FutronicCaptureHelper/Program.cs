using System.Runtime.InteropServices;
using System.Text.Json;

const int DetectionThreshold = 350;
const int Dose = 4;

try
{
    var probeOnly = args.Any(arg => string.Equals(arg, "--probe", StringComparison.OrdinalIgnoreCase));
    var sdkProbeOnly = args.Any(arg => string.Equals(arg, "--sdk-probe", StringComparison.OrdinalIgnoreCase));
    var sdkEnroll = args.Any(arg => string.Equals(arg, "--sdk-enroll", StringComparison.OrdinalIgnoreCase));
    var sdkIdentify = args.Any(arg => string.Equals(arg, "--sdk-identify", StringComparison.OrdinalIgnoreCase));

    if (sdkProbeOnly)
    {
        ProbeRecognitionSdk();
        return;
    }
    if (sdkEnroll)
    {
        EnrollWithRecognitionSdk();
        return;
    }
    if (sdkIdentify)
    {
        IdentifyWithRecognitionSdk();
        return;
    }

    var handle = NativeMethods.ftrScanOpenDevice();
    if (handle == IntPtr.Zero)
    {
        Fail("Unable to open Futronic scanner.");
        return;
    }

    try
    {
        if (probeOnly)
        {
            Console.WriteLine("PROBE_OK");
            return;
        }

        NativeMethods.ftrScanSetDiodesStatus(handle, 0, 255);

        var deadline = DateTime.UtcNow.AddSeconds(12);
        var fingerDetected = false;
        while (DateTime.UtcNow < deadline)
        {
            if (!NativeMethods.ftrScanIsFingerPresent(handle, out var frame))
            {
                Thread.Sleep(50);
                continue;
            }

            if (frame.nContrastOnDose2 > DetectionThreshold)
            {
                fingerDetected = true;
                break;
            }

            Thread.Sleep(50);
        }

        if (!fingerDetected)
        {
            Fail("No finger detected on the Futronic scanner. Place a finger firmly on the sensor and try again.");
            return;
        }

        NativeMethods.ftrScanSetDiodesStatus(handle, 255, 0);

        if (!NativeMethods.ftrScanGetImageSize(handle, out var imageSize))
        {
            Fail("Unable to read Futronic image size.");
            return;
        }

        var buffer = new byte[imageSize.nImageSize];
        if (!NativeMethods.ftrScanGetImage(handle, Dose, buffer))
        {
            Fail("Unable to capture fingerprint image.");
            return;
        }

        var payload = new CapturePayload
        {
            Width = imageSize.nWidth,
            Height = imageSize.nHeight,
            ImageHex = Convert.ToHexString(buffer).ToLowerInvariant(),
        };

        Console.WriteLine(JsonSerializer.Serialize(payload));
    }
    finally
    {
        try
        {
            NativeMethods.ftrScanSetDiodesStatus(handle, 0, 0);
        }
        catch
        {
        }

        NativeMethods.ftrScanCloseDevice(handle);
    }
}
catch (Exception ex)
{
    Fail($"Futronic helper crashed: {ex.GetType().Name}: {ex.Message}");
}

static void EnrollWithRecognitionSdk()
{
    WithConfiguredRecognitionSdk(maxModels: 3, () =>
    {
        var templateSize = GetSdkParameter(SdkConstants.MaxTemplateSize);
        var buffer = Marshal.AllocHGlobal(checked((int)templateSize));
        try
        {
            var template = new SdkData { Size = templateSize, Data = buffer };
            var enrollment = new SdkEnrollmentData { Size = (uint)Marshal.SizeOf<SdkEnrollmentData>() };
            var result = SdkNativeMethods.FTREnrollX(
                IntPtr.Zero,
                SdkConstants.PurposeEnroll,
                ref template,
                ref enrollment
            );
            EnsureSdkSuccess(result, "Official fingerprint enrollment");
            if (template.Size == 0 || template.Size > templateSize)
            {
                throw new InvalidOperationException("Futronic returned an invalid enrollment template size.");
            }
            var bytes = new byte[checked((int)template.Size)];
            Marshal.Copy(buffer, bytes, 0, bytes.Length);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                success = true,
                version = 4,
                algorithm = "Futronic FTRAPI minutiae",
                sdk_version = "4.2.2029.176",
                sample_count = 3,
                quality_score = enrollment.Quality,
                template_base64 = Convert.ToBase64String(bytes),
            }));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    });
}

static void IdentifyWithRecognitionSdk()
{
    var request = JsonSerializer.Deserialize<IdentifyRequest>(
        Console.In.ReadToEnd(),
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
    ) ?? throw new InvalidOperationException("Fingerprint identification request is empty.");
    if (request.Candidates.Count == 0)
    {
        throw new InvalidOperationException("Fingerprint identification has no candidate templates.");
    }

    WithConfiguredRecognitionSdk(maxModels: 1, () =>
    {
        var maximumSize = GetSdkParameter(SdkConstants.MaxTemplateSize);
        var liveBuffer = Marshal.AllocHGlobal(checked((int)maximumSize));
        var allocations = new List<IntPtr>();
        try
        {
            var liveTemplate = new SdkData { Size = maximumSize, Data = liveBuffer };
            var enrollment = new SdkEnrollmentData { Size = (uint)Marshal.SizeOf<SdkEnrollmentData>() };
            EnsureSdkSuccess(
                SdkNativeMethods.FTREnrollX(
                    IntPtr.Zero,
                    SdkConstants.PurposeIdentify,
                    ref liveTemplate,
                    ref enrollment
                ),
                "Live fingerprint template capture"
            );
            EnsureSdkSuccess(
                SdkNativeMethods.FTRSetBaseTemplate(ref liveTemplate),
                "Live fingerprint identification setup"
            );

            var recordSize = Marshal.SizeOf<SdkIdentifyRecord>();
            var recordsPointer = Marshal.AllocHGlobal(recordSize * request.Candidates.Count);
            allocations.Add(recordsPointer);
            for (var index = 0; index < request.Candidates.Count; index++)
            {
                var candidate = request.Candidates[index];
                var templateBytes = Convert.FromBase64String(candidate.TemplateBase64);
                var templateBuffer = Marshal.AllocHGlobal(templateBytes.Length);
                allocations.Add(templateBuffer);
                Marshal.Copy(templateBytes, 0, templateBuffer, templateBytes.Length);
                var dataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<SdkData>());
                allocations.Add(dataPointer);
                Marshal.StructureToPtr(
                    new SdkData { Size = (uint)templateBytes.Length, Data = templateBuffer },
                    dataPointer,
                    false
                );
                Marshal.StructureToPtr(
                    new SdkIdentifyRecord
                    {
                        Key0 = unchecked((uint)candidate.Id),
                        Data = dataPointer,
                    },
                    recordsPointer + (index * recordSize),
                    false
                );
            }

            var matchSize = Marshal.SizeOf<SdkMatchedRecord>();
            var matchesPointer = Marshal.AllocHGlobal(matchSize * request.Candidates.Count);
            allocations.Add(matchesPointer);
            var identifyArray = new SdkIdentifyArray
            {
                TotalNumber = (uint)request.Candidates.Count,
                Members = recordsPointer,
            };
            var matchedArray = new SdkMatchedArray
            {
                TotalNumber = (uint)request.Candidates.Count,
                Members = matchesPointer,
            };
            EnsureSdkSuccess(
                SdkNativeMethods.FTRIdentify(ref identifyArray, out var matchCount, ref matchedArray),
                "Official fingerprint identification"
            );

            var matches = new List<object>();
            for (var index = 0; index < matchCount; index++)
            {
                var match = Marshal.PtrToStructure<SdkMatchedRecord>(
                    matchesPointer + (index * matchSize)
                );
                matches.Add(new { id = unchecked((int)match.Key0), far = match.FarAttained });
            }
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                success = true,
                quality_score = enrollment.Quality,
                matches,
            }));
        }
        finally
        {
            Marshal.FreeHGlobal(liveBuffer);
            foreach (var pointer in allocations)
            {
                Marshal.FreeHGlobal(pointer);
            }
        }
    });
}

static void WithConfiguredRecognitionSdk(int maxModels, Action operation)
{
    var initialized = false;
    uint lastSignal = SdkConstants.SignalUndefined;
    SdkControlCallback? callback = null;
    try
    {
        EnsureSdkSuccess(SdkNativeMethods.FTRInitialize(), "Futronic recognition SDK initialization");
        initialized = true;
        EnsureSdkSuccess(
            SdkNativeMethods.FTRSetParam(
                SdkConstants.FrameSource,
                new IntPtr(SdkConstants.FutronicUsbFrameSource)
            ),
            "Futronic USB scanner selection"
        );
        EnsureSdkSuccess(
            SdkNativeMethods.FTRSetParam(SdkConstants.MaxModels, new IntPtr(maxModels)),
            "Futronic enrollment sample configuration"
        );
        EnsureSdkSuccess(
            SdkNativeMethods.FTRSetParam(
                SdkConstants.MaximumFarRequested,
                new IntPtr(SdkConstants.FarOneInOneHundredThousand)
            ),
            "Futronic security threshold configuration"
        );
        callback = (
            IntPtr context,
            uint stateMask,
            ref uint response,
            uint signal,
            IntPtr bitmap
        ) =>
        {
            response = SdkConstants.Continue;
            if ((stateMask & SdkConstants.StateSignalProvided) != 0 && signal != lastSignal)
            {
                if (signal == SdkConstants.SignalTouchSensor)
                {
                    Console.Error.WriteLine("Place the same finger flat on the scanner.");
                }
                else if (signal == SdkConstants.SignalTakeOff)
                {
                    Console.Error.WriteLine("Lift the finger completely from the scanner.");
                }
                else if (signal == SdkConstants.SignalFakeSource)
                {
                    Console.Error.WriteLine("The scanner rejected the sample. Use a real finger.");
                }
                Console.Error.Flush();
                lastSignal = signal;
            }
        };
        EnsureSdkSuccess(
            SdkNativeMethods.FTRSetParam(
                SdkConstants.ControlCallback,
                Marshal.GetFunctionPointerForDelegate(callback)
            ),
            "Futronic capture callback configuration"
        );
        operation();
        GC.KeepAlive(callback);
    }
    finally
    {
        if (initialized)
        {
            SdkNativeMethods.FTRTerminate();
        }
    }
}

static uint GetSdkParameter(int parameter)
{
    EnsureSdkSuccess(
        SdkNativeMethods.FTRGetParam(parameter, out var value),
        $"Futronic SDK parameter {parameter}"
    );
    return value;
}

static void EnsureSdkSuccess(int result, string operation)
{
    if (result != 0)
    {
        throw new InvalidOperationException($"{operation} failed with SDK code {result}.");
    }
}

static void ProbeRecognitionSdk()
{
    const int FtrRetcodeOk = 0;
    const int FtrParamImageWidth = 1;
    const int FtrParamImageHeight = 2;
    const int FtrParamFrameSource = 4;
    const int FtrParamMaxTemplateSize = 6;
    const int FtrParamMaxModels = 10;
    const int FutronicUsbFrameSource = 1;

    var initialized = false;
    try
    {
        var result = SdkNativeMethods.FTRInitialize();
        if (result != FtrRetcodeOk)
        {
            Fail($"Futronic recognition SDK initialization failed with code {result}.");
            return;
        }
        initialized = true;

        result = SdkNativeMethods.FTRSetParam(FtrParamFrameSource, new IntPtr(FutronicUsbFrameSource));
        if (result != FtrRetcodeOk)
        {
            Fail($"Futronic recognition SDK could not select the USB scanner (code {result}).");
            return;
        }

        result = SdkNativeMethods.FTRSetParam(FtrParamMaxModels, new IntPtr(3));
        if (result != FtrRetcodeOk)
        {
            Fail($"Futronic recognition SDK could not configure enrollment samples (code {result}).");
            return;
        }

        if (SdkNativeMethods.FTRGetParam(FtrParamImageWidth, out var width) != FtrRetcodeOk
            || SdkNativeMethods.FTRGetParam(FtrParamImageHeight, out var height) != FtrRetcodeOk
            || SdkNativeMethods.FTRGetParam(FtrParamMaxTemplateSize, out var templateSize) != FtrRetcodeOk)
        {
            Fail("Futronic recognition SDK parameters could not be read.");
            return;
        }

        Console.WriteLine(JsonSerializer.Serialize(new
        {
            success = true,
            sdk = "Futronic FTRAPI",
            width,
            height,
            template_size = templateSize,
            enrollment_samples = 3,
        }));
    }
    finally
    {
        if (initialized)
        {
            SdkNativeMethods.FTRTerminate();
        }
    }
}

static void Fail(string message)
{
    Console.Error.WriteLine(message);
    Environment.ExitCode = 1;
}

internal sealed class CapturePayload
{
    public int Width { get; set; }
    public int Height { get; set; }
    public string ImageHex { get; set; } = string.Empty;
}

internal sealed class IdentifyRequest
{
    public List<IdentifyCandidate> Candidates { get; set; } = [];
}

internal sealed class IdentifyCandidate
{
    public int Id { get; set; }
    public string TemplateBase64 { get; set; } = string.Empty;
}

internal static class NativeMethods
{
    [DllImport("ftrScanApi.dll")]
    internal static extern IntPtr ftrScanOpenDevice();

    [DllImport("ftrScanApi.dll")]
    internal static extern void ftrScanCloseDevice(IntPtr handle);

    [DllImport("ftrScanApi.dll")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool ftrScanIsFingerPresent(IntPtr handle, out FrameParameters frameParameters);

    [DllImport("ftrScanApi.dll")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool ftrScanSetDiodesStatus(IntPtr handle, byte green, byte red);

    [DllImport("ftrScanApi.dll")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool ftrScanGetImageSize(IntPtr handle, out ImageSize imageSize);

    [DllImport("ftrScanApi.dll")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool ftrScanGetImage(IntPtr handle, int dose, byte[] buffer);
}

internal static class SdkNativeMethods
{
    [DllImport("FTRAPI.dll", CallingConvention = CallingConvention.Winapi)]
    internal static extern int FTRInitialize();

    [DllImport("FTRAPI.dll", CallingConvention = CallingConvention.Winapi)]
    internal static extern void FTRTerminate();

    [DllImport("FTRAPI.dll", CallingConvention = CallingConvention.Winapi)]
    internal static extern int FTRSetParam(int parameter, IntPtr value);

    [DllImport("FTRAPI.dll", CallingConvention = CallingConvention.Winapi)]
    internal static extern int FTRGetParam(int parameter, out uint value);

    [DllImport("FTRAPI.dll", CallingConvention = CallingConvention.Winapi)]
    internal static extern int FTREnrollX(
        IntPtr userContext,
        uint purpose,
        ref SdkData template,
        ref SdkEnrollmentData enrollmentData
    );

    [DllImport("FTRAPI.dll", CallingConvention = CallingConvention.Winapi)]
    internal static extern int FTRSetBaseTemplate(ref SdkData template);

    [DllImport("FTRAPI.dll", CallingConvention = CallingConvention.Winapi)]
    internal static extern int FTRIdentify(
        ref SdkIdentifyArray identifyArray,
        out uint matchCount,
        ref SdkMatchedArray matchedArray
    );
}

internal static class SdkConstants
{
    internal const int FrameSource = 4;
    internal const int ControlCallback = 5;
    internal const int MaxTemplateSize = 6;
    internal const int MaximumFarRequested = 7;
    internal const int MaxModels = 10;
    internal const int FutronicUsbFrameSource = 1;
    internal const uint PurposeIdentify = 2;
    internal const uint PurposeEnroll = 3;
    internal const uint Continue = 2;
    internal const uint StateSignalProvided = 0x02;
    internal const uint SignalUndefined = 0;
    internal const uint SignalTouchSensor = 1;
    internal const uint SignalTakeOff = 2;
    internal const uint SignalFakeSource = 3;
    internal const int FarOneInOneHundredThousand = 21475;
}

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
internal delegate void SdkControlCallback(
    IntPtr context,
    uint stateMask,
    ref uint response,
    uint signal,
    IntPtr bitmap
);

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct SdkData
{
    public uint Size;
    public IntPtr Data;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct SdkEnrollmentData
{
    public uint Size;
    public uint Quality;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct SdkIdentifyRecord
{
    public uint Key0;
    public uint Key1;
    public uint Key2;
    public uint Key3;
    public IntPtr Data;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct SdkIdentifyArray
{
    public uint TotalNumber;
    public IntPtr Members;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct SdkMatchedRecord
{
    public uint Key0;
    public uint Key1;
    public uint Key2;
    public uint Key3;
    public uint FarAttained;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct SdkMatchedArray
{
    public uint TotalNumber;
    public IntPtr Members;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FakeReplicaParameters
{
    [MarshalAs(UnmanagedType.I1)]
    public bool bCalculated;
    public int nCalculatedSum1;
    public int nCalculatedSumFuzzy;
    public int nCalculatedSumEmpty;
    public int nCalculatedSum2;
    public double dblCalculatedTremor;
    public double dblCalculatedValue;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FrameParameters
{
    public int nContrastOnDose2;
    public int nContrastOnDose4;
    public int nDose;
    public int nBrightnessOnDose1;
    public int nBrightnessOnDose2;
    public int nBrightnessOnDose3;
    public int nBrightnessOnDose4;
    public FakeReplicaParameters FakeReplicaParams;
    public FakeReplicaParameters Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ImageSize
{
    public int nWidth;
    public int nHeight;
    public int nImageSize;
}
