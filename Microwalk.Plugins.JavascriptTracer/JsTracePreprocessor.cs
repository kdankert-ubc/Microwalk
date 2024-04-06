﻿using System.Collections.Concurrent;
using System.Text;
using Microwalk.FrameworkBase;
using Microwalk.FrameworkBase.Configuration;
using Microwalk.FrameworkBase.Exceptions;
using Microwalk.FrameworkBase.Stages;
using Microwalk.FrameworkBase.TraceFormat;
using Microwalk.FrameworkBase.TraceFormat.TraceEntryTypes;
using Microwalk.FrameworkBase.Utilities;

namespace Microwalk.Plugins.JavascriptTracer;

[FrameworkModule("js", "Preprocesses JavaScript traces.")]
public class JsTracePreprocessor : PreprocessorStage
{
    public override bool SupportsParallelism => true;

    /// <summary>
    /// Determines whether preprocessed traces are stored to disk.
    /// </summary>
    private bool _storeTraces;

    /// <summary>
    /// The preprocessed trace output directory.
    /// </summary>
    private DirectoryInfo? _outputDirectory;

    /// <summary>
    /// The MAP file output directory.
    /// </summary>
    private DirectoryInfo _mapDirectory = null!;

    /// <summary>
    /// Number of bits for column numbers encoded into an 32-bit integer.
    /// </summary>
    private int _columnsBits = 13;

    private uint _columnMask;

    /// <summary>
    /// Determines whether the next incoming test case is the first one.
    /// </summary>
    private bool _firstTestcase = true;

    /// <summary>
    /// Protects the first test case variable.
    /// </summary>
    private readonly SemaphoreSlim _firstTestcaseSemaphore = new(1, 1);

    /// <summary>
    /// Trace prefix data.
    /// </summary>
    private TracePrefixFile _tracePrefix = null!;

    /// <summary>
    /// Next heap allocation offset after processing the trace prefix.
    /// </summary>
    private ulong _prefixNextHeapAllocationAddress = 0;

    /// <summary>
    /// Heap allocations from the trace prefix.
    /// </summary>
    private Dictionary<int, HeapObjectData>? _prefixHeapObjects;

    /// <summary>
    /// Compressed lines from the trace prefix, indexed by line ID.
    /// </summary>
    private Dictionary<int, string>? _prefixCompressedLinesLookup;

    /// <summary>
    /// ID of the external functions image.
    /// </summary>
    private int _externalFunctionsImageId;

    /// <summary>
    /// Image data of external functions ("E:&lt;function name&gt;").
    /// </summary>
    private TracePrefixFile.ImageFileInfo _externalFunctionsImage = null!;

    /// <summary>
    /// Metadata and lookup objects for loaded "images" (= scripts), indexed by script IDs.
    /// </summary>
    private readonly List<ImageData> _imageData = new();

    /// <summary>
    /// Catch-all address for unknown external function locations.
    /// Is used for returns from external functions, where we don't know the precise source location.
    /// </summary>
    private uint _catchAllExternalFunctionAddress = 1;

    /// <summary>
    /// The next address which is assigned to an external function.
    /// Initialized with 2, as <see cref="_catchAllExternalFunctionAddress"/> is 1.
    /// </summary>
    private uint _currentExternalFunctionAddress = 2;

    /// <summary>
    /// Lookup for addresses assigned to external functions "[extern]:functionName", indexed by functionName.
    /// </summary>
    private ConcurrentDictionary<string, uint>? _externalFunctionAddresses;

    /// <summary>
    /// Lookup for addresses assigned to external functions "[extern]:functionName", indexed by functionName.
    /// 
    /// The variable is used by the prefix preprocessing step exclusively, the data is copied to <see cref="_externalFunctionAddresses"/> afterwards.
    /// This is purely a performance optimization, as the prefix is processed exclusively at the beginning and we thus don't need the concurrency of <see cref="ConcurrentDictionary{TKey,TValue}"/>.
    /// </summary>
    private Dictionary<string, uint>? _externalFunctionAddressesPrefix = new();

    /// <summary>
    /// Requested MAP entries, which will be generated after preprocessing is done.
    /// This dictionary is used as a set, so the value is always ignored.
    /// </summary>
    private ConcurrentDictionary<(int imageId, uint relativeAddress), object?>? _requestedMapEntries;

    /// <summary>
    /// Requested MAP entries, which will be generated after preprocessing is done.
    /// This dictionary is used as a set, so the value is always ignored.
    ///
    /// During prefix processing, we use a non-thread-safe dictionary for performance.
    /// </summary>
    private Dictionary<(int imageId, uint relativeAddress), object?>? _requestedMapEntriesPrefix = new();

    public override async Task PreprocessTraceAsync(TraceEntity traceEntity)
    {
        // Input check
        if(traceEntity.RawTraceFilePath == null)
            throw new Exception("Raw trace file path is null. Is the trace stage missing?");

        // First test case?
        await _firstTestcaseSemaphore.WaitAsync();
        try
        {
            if(_firstTestcase)
            {
                await Logger.LogDebugAsync("[preprocess] Preprocessing prefix");

                // Paths
                string rawTraceFileDirectory = Path.GetDirectoryName(traceEntity.RawTraceFilePath) ?? throw new Exception($"Could not determine directory: {traceEntity.RawTraceFilePath}");
                string scriptsFilePath = Path.Combine(rawTraceFileDirectory, "scripts.txt");
                string tracePrefixFilePath = Path.Combine(rawTraceFileDirectory, "prefix.trace");

                // Read scripts data and translate into image file format
                string[] scriptsFileLines = await File.ReadAllLinesAsync(scriptsFilePath);
                int maxImageNameLength = 8; // [extern]
                int currentImageFileId = 0;
                foreach(string line in scriptsFileLines)
                {
                    string[] scriptData = line.Split('\t');

                    // The script IDs are expected to be zero-based and consecutive
                    int imageFileId = ParseInt32NotSigned(scriptData[0]);
                    if(currentImageFileId != imageFileId)
                        throw new Exception($"Unexpected script ID ({imageFileId}), expected {currentImageFileId}.");

                    var imageFile = new TracePrefixFile.ImageFileInfo
                    {
                        Id = imageFileId,
                        Interesting = true,
                        StartAddress = (ulong)imageFileId << 32,
                        EndAddress = ((ulong)imageFileId << 32) | 0xFFFFFFFFul,
                        Name = scriptData[1]
                    };
                    _imageData.Add(new ImageData(imageFile));

                    if(imageFile.Name.Length > maxImageNameLength)
                        maxImageNameLength = imageFile.Name.Length;

                    ++currentImageFileId;
                }

                // Add dummy image for [extern] functions
                _externalFunctionsImageId = currentImageFileId;
                _externalFunctionsImage = new TracePrefixFile.ImageFileInfo
                {
                    Id = _externalFunctionsImageId,
                    Interesting = true,
                    StartAddress = (ulong)_externalFunctionsImageId << 32,
                    EndAddress = ((ulong)_externalFunctionsImageId << 32) | 0xFFFFFFFFul,
                    Name = "[extern]"
                };
                var externalFunctionsImageData = new ImageData(_externalFunctionsImage);
                _imageData.Add(externalFunctionsImageData);

                // Add catch-all entry for returns from unknown locations
                _requestedMapEntriesPrefix!.Add((_externalFunctionsImageId, _catchAllExternalFunctionAddress), null);
                externalFunctionsImageData.FunctionNameLookupPrefix!.Add((_catchAllExternalFunctionAddress, _catchAllExternalFunctionAddress), "[unknown]");

                // Prepare writer for serializing trace data
                // We initialize it with some robust initial capacity, to reduce amount of copying while keeping memory overhead low
                using var tracePrefixFileWriter = new FastBinaryBufferWriter(_imageData.Count * (32 + maxImageNameLength) + 1 * 1024 * 1024);

                // Write image files
                tracePrefixFileWriter.WriteInt32(_imageData.Count);
                foreach(var imageData in _imageData)
                    imageData.ImageFileInfo.Store(tracePrefixFileWriter);

                // Load and parse trace prefix data
                PreprocessFile(tracePrefixFilePath, tracePrefixFileWriter, "[preprocess:prefix]");

                // Create trace prefix object
                var preprocessedTracePrefixData = tracePrefixFileWriter.Buffer.AsMemory(0, tracePrefixFileWriter.Length);
                _tracePrefix = new TracePrefixFile(preprocessedTracePrefixData);

                // Store to disk?
                if(_storeTraces)
                {
                    string outputPath = Path.Combine(_outputDirectory!.FullName, "prefix.trace.preprocessed");
                    await using var writer = new BinaryWriter(File.Open(outputPath, FileMode.Create, FileAccess.Write, FileShare.None));
                    writer.Write(preprocessedTracePrefixData.Span);
                }

                // Initialize shared dictionaries
                _externalFunctionAddresses = new ConcurrentDictionary<string, uint>(_externalFunctionAddressesPrefix!);
                _externalFunctionAddressesPrefix = null;
                _requestedMapEntries = new ConcurrentDictionary<(int imageId, uint relativeAddress), object?>(_requestedMapEntriesPrefix!);
                _requestedMapEntriesPrefix = null;
                foreach(var imageData in _imageData)
                {
                    imageData.FunctionNameLookup = new ConcurrentDictionary<(uint start, uint end), string>(imageData.FunctionNameLookupPrefix!);
                    imageData.FunctionNameLookupPrefix = null;
                    imageData.RelativeAddressLookup = new ConcurrentDictionary<string, (uint start, uint end)>(imageData.RelativeAddressLookupPrefix!);
                    imageData.RelativeAddressLookupPrefix = null;
                }

                _firstTestcase = false;
            }
        }
        catch
        {
            // Ensure that other threads don't try to process the prefix as well, leading to confusing stack traces
            _firstTestcase = false;

            throw;
        }
        finally
        {
            _firstTestcaseSemaphore.Release();
        }

        // Preprocess trace data
        await Logger.LogDebugAsync($"[preprocess:{traceEntity.Id}] Preprocessing trace");
        if(_storeTraces)
        {
            // Write trace to file, do not keep it in memory
            string preprocessedTraceFilePath = Path.Combine(_outputDirectory!.FullName, Path.GetFileName(traceEntity.RawTraceFilePath) + ".preprocessed");
            using var traceFileWriter = new FastBinaryFileWriter(preprocessedTraceFilePath);
            PreprocessFile(traceEntity.RawTraceFilePath, traceFileWriter, $"[preprocess:{traceEntity.Id}]");
            traceFileWriter.Flush();

            // Create trace file object
            traceEntity.PreprocessedTraceFile = new TraceFile(_tracePrefix, preprocessedTraceFilePath);
        }
        else
        {
            // Keep trace in memory for immediate analysis
            using var traceFileWriter = new FastBinaryBufferWriter(1 * 1024 * 1024);
            PreprocessFile(traceEntity.RawTraceFilePath, traceFileWriter, $"[preprocess:{traceEntity.Id}]");

            // Create trace file object
            var preprocessedTraceData = traceFileWriter.Buffer.AsMemory(0, traceFileWriter.Length);
            traceEntity.PreprocessedTraceFile = new TraceFile(_tracePrefix, preprocessedTraceData);
        }
    }

    private void PreprocessFile(string inputFileName, IFastBinaryWriter traceFileWriter, string logPrefix)
    {
        // Read entire raw trace into memory, for faster processing
        using var inputFileStream = File.Open(inputFileName, new FileStreamOptions
        {
            Access = FileAccess.Read,
            Mode = FileMode.Open,
            Options = FileOptions.SequentialScan,
            BufferSize = 1 * 1024 * 1024
        });
        using var inputFileStreamReader = new StreamReader(inputFileStream, Encoding.UTF8);

        // If we are writing to memory, set the capacity of the writer to a rough estimate of the preprocessed file size,
        // in order to avoid reallocations and expensive copying
        if(!_firstTestcase && traceFileWriter is FastBinaryBufferWriter binaryBufferWriter)
            binaryBufferWriter.ResizeBuffer((int)inputFileStream.Length);

        // Preallocated trace entry variables (only needed for serialization)
        Branch branchEntry = new();
        HeapAllocation heapAllocationEntry = new();
        HeapMemoryAccess heapMemoryAccessEntry = new();

        // Helper function for adding requested MAP entries without having to check _firstTestcase every time
        // We cannot cast to IDictionary, as the TryAdd extension does not work with ConcurrentDictionary
        Func<(int imageId, uint relativeAddress), object?, bool> tryAddRequestedMapEntry = _firstTestcase
            ? (key, value) => _requestedMapEntriesPrefix!.TryAdd(key, value)
            : (key, value) => _requestedMapEntries!.TryAdd(key, value);

        // Parse trace entries
        (TracePrefixFile.ImageFileInfo imageFileInfo, uint address)? lastRet1Entry = null;
        Dictionary<int, HeapObjectData> heapObjects = _prefixHeapObjects == null ? new() : new(_prefixHeapObjects);
        Dictionary<int, string> compressedLinesLookup = _prefixCompressedLinesLookup == null ? new() : new(_prefixCompressedLinesLookup);
        ulong nextHeapAllocationAddress = _prefixNextHeapAllocationAddress;
        const uint heapAllocationChunkSize = 0x100000;
        int lastLineId = 0;
        int inputBufferLength = 0;
        int inputBufferPosition = 0;
        char[] inputBuffer = new char[1 * 1024 * 1024];
        char[] lineBuffer = new char[1024]; // For storing a single, decompressed line
        while(true)
        {
            // Empty buffer? -> Read next chunk
            if(inputBufferPosition == inputBufferLength)
            {
                inputBufferLength = inputFileStreamReader.ReadBlock(inputBuffer);
                if(inputBufferLength == 0)
                    break;

                inputBufferPosition = 0;
            }

            // Find end of next line in input buffer
            int lineEnd = inputBufferPosition;
            Span<char> currentInputFileLineSpan = Span<char>.Empty;
            bool foundNewLine = false;
            while(lineEnd < inputBufferLength)
            {
                if(inputBuffer[lineEnd] == '\n')
                {
                    currentInputFileLineSpan = inputBuffer.AsSpan(inputBufferPosition..lineEnd);
                    foundNewLine = true;
                    break;
                }

                ++lineEnd;
            }

            // If we could not find the line end in the buffer, we need to read more data
            if(!foundNewLine)
            {
                // Copy beginning of line to buffer begin
                for(int i = inputBufferPosition; i < inputBufferLength; ++i)
                    inputBuffer[i - inputBufferPosition] = inputBuffer[i];
                inputBufferLength -= inputBufferPosition;
                inputBufferPosition = 0;

                // Append the new data
                int dataRead = inputFileStreamReader.ReadBlock(inputBuffer.AsSpan(inputBufferLength..));
                inputBufferLength += dataRead;
                if(dataRead == 0)
                {
                    // No data retrieved, either the buffer is entirely full or the file has ended
                    // Since the buffer is _very_ large, we just assume the latter, and fail otherwise
                    if(inputFileStream.Position < inputFileStream.Length)
                        throw new Exception("The file read buffer is too small (no data returned).");

                    currentInputFileLineSpan = inputBuffer.AsSpan(..inputBufferLength);
                }
                else
                {
                    // Look for newline or buffer end
                    lineEnd = inputBufferPosition;
                    while(lineEnd < inputBufferLength)
                    {
                        if(inputBuffer[lineEnd] == '\n')
                        {
                            currentInputFileLineSpan = inputBuffer.AsSpan(inputBufferPosition..lineEnd);
                            foundNewLine = true;
                            break;
                        }

                        ++lineEnd;
                    }

                    if(!foundNewLine)
                    {
                        if(inputFileStream.Position < inputFileStream.Length)
                            throw new Exception("The file read buffer is too small (could not find line end).");

                        currentInputFileLineSpan = inputBuffer.AsSpan(inputBufferPosition..lineEnd);
                    }
                }
            }

            // Update current input buffer position
            // The line span automatically skips the \n, as the end of the range is exclusive
            inputBufferPosition = lineEnd + 1;

            // Skip empty lines
            if(currentInputFileLineSpan.Length == 0)
                continue;

            // Read merged lines
            int pos = 0;
            while(pos < currentInputFileLineSpan.Length)
            {
                // Parse current control character
                char firstChar = currentInputFileLineSpan[pos];
                int lineId;
                ReadOnlySpan<char> lineEndPart = ReadOnlySpan<char>.Empty;
                if(firstChar == 'L')
                {
                    // Line info
                    int separatorIndex = currentInputFileLineSpan.Slice(pos + 2).IndexOf('|');
                    int lId = ParseInt32NotSigned(currentInputFileLineSpan.Slice(pos + 2, separatorIndex));
                    string lContent = new string(currentInputFileLineSpan.Slice(pos + 2 + separatorIndex + 1));

                    compressedLinesLookup.Add(lId, lContent);

                    // The line is fully consumed
                    break;
                }
                else if(firstChar is >= 'a' and <= 's')
                {
                    // Line ID, relative

                    lineId = lastLineId + (firstChar - 'j');
                    lastLineId = lineId;

                    // Is this a prefixed line?
                    ++pos;
                    if(pos < currentInputFileLineSpan.Length && currentInputFileLineSpan[pos] == '|')
                    {
                        // Read remaining line part
                        lineEndPart = currentInputFileLineSpan.Slice(pos + 1);

                        // The line is fully consumed
                        pos = currentInputFileLineSpan.Length;
                    }
                }
                else if(char.IsDigit(firstChar))
                {
                    // Line ID, absolute

                    int numDigits = 0;
                    for(int i = pos; i < currentInputFileLineSpan.Length; ++i)
                    {
                        if(!char.IsDigit(currentInputFileLineSpan[i]))
                            break;
                        ++numDigits;
                    }

                    lineId = ParseInt32NotSigned(currentInputFileLineSpan.Slice(pos, numDigits));
                    lastLineId = lineId;

                    // Is this a prefixed line?
                    pos += numDigits;
                    if(pos < currentInputFileLineSpan.Length && currentInputFileLineSpan[pos] == '|')
                    {
                        // Read remaining line part
                        lineEndPart = currentInputFileLineSpan.Slice(pos + 1);

                        // The line is fully consumed
                        pos = currentInputFileLineSpan.Length;
                    }
                }
                else
                    throw new Exception($"{logPrefix} Unexpected control character: '{firstChar}' in line \"{new string(currentInputFileLineSpan)}\"");

                // Extract line
                if(!compressedLinesLookup.TryGetValue(lineId, out string? decompressedLine))
                    throw new Exception($"{logPrefix} Could not resolve compressed line #{lineId}");

                // Compose final decompressed line
                decompressedLine.CopyTo(lineBuffer);
                lineEndPart.CopyTo(lineBuffer.AsSpan(decompressedLine.Length));
                ReadOnlySpan<char> line = lineBuffer.AsSpan(0, decompressedLine.Length + lineEndPart.Length);

                // Parse decompressed line
                const char separator = ';';
                var lineParts = line;
                char entryType = NextSplit(ref lineParts, separator)[0];
                switch(entryType)
                {
                    case 'c':
                    {
                        // Parse line
                        var sourceScriptIdPart = NextSplit(ref lineParts, separator);
                        var sourcePart = NextSplit(ref lineParts, separator);
                        var destinationScriptIdPart = NextSplit(ref lineParts, separator);
                        var destinationPart = NextSplit(ref lineParts, separator);
                        var namePart = NextSplit(ref lineParts, separator);

                        int sourceScriptId = ParseInt32NotSigned(sourceScriptIdPart);
                        int? destinationScriptId = destinationScriptIdPart.Equals("E", StringComparison.Ordinal) ? null : ParseInt32NotSigned(destinationScriptIdPart);

                        // Resolve code locations
                        var source = ResolveLineInfo(sourceScriptId, sourcePart);
                        var destination = ResolveLineInfo(destinationScriptId, destinationPart);

                        // Produce MAP entries
                        tryAddRequestedMapEntry((source.imageData.ImageFileInfo.Id, source.relativeStartAddress), null);
                        tryAddRequestedMapEntry((destination.imageData.ImageFileInfo.Id, destination.relativeStartAddress), null);
                        tryAddRequestedMapEntry((destination.imageData.ImageFileInfo.Id, destination.relativeEndAddress), null);

                        if(_firstTestcase)
                        {
                            // Record function name, if it is not already known
                            destination.imageData.FunctionNameLookupPrefix!.TryAdd((destination.relativeStartAddress, destination.relativeEndAddress), new string(namePart));

                            // Do not trace branches in prefix mode
                            break;
                        }

                        // Record function name, if it is not already known
                        destination.imageData.FunctionNameLookup!.TryAdd((destination.relativeStartAddress, destination.relativeEndAddress), new string(namePart));

                        // Record call
                        branchEntry.BranchType = Branch.BranchTypes.Call;
                        branchEntry.Taken = true;
                        branchEntry.SourceImageId = source.imageData.ImageFileInfo.Id;
                        branchEntry.SourceInstructionRelativeAddress = source.relativeStartAddress;
                        branchEntry.DestinationImageId = destination.imageData.ImageFileInfo.Id;
                        branchEntry.DestinationInstructionRelativeAddress = destination.relativeStartAddress;
                        branchEntry.Store(traceFileWriter);

                        break;
                    }

                    case 'r':
                    {
                        // Parse line
                        var scriptIdPart = NextSplit(ref lineParts, separator);
                        var locationPart = NextSplit(ref lineParts, separator);

                        // Resolve code locations
                        int scriptId = ParseInt32NotSigned(scriptIdPart);
                        var location = ResolveLineInfo(scriptId, locationPart);

                        // Produce MAP entries
                        tryAddRequestedMapEntry((location.imageData.ImageFileInfo.Id, location.relativeStartAddress), null);

                        // Do not trace branches in prefix mode
                        if(_firstTestcase)
                            break;

                        // Remember for next Ret2 entry
                        lastRet1Entry = (location.imageData.ImageFileInfo, location.relativeStartAddress);

                        break;
                    }

                    case 'R':
                    {
                        // Parse line
                        var scriptIdPart = NextSplit(ref lineParts, separator);
                        var locationPart = NextSplit(ref lineParts, separator);

                        // Resolve code locations
                        int scriptId = ParseInt32NotSigned(scriptIdPart);
                        var location = ResolveLineInfo(scriptId, locationPart);

                        // Produce MAP entries
                        tryAddRequestedMapEntry((location.imageData.ImageFileInfo.Id, location.relativeStartAddress), null);

                        // Do not trace branches in prefix mode
                        if(_firstTestcase)
                            break;

                        // Create branch entry
                        branchEntry.BranchType = Branch.BranchTypes.Return;
                        branchEntry.Taken = true;
                        branchEntry.DestinationImageId = location.imageData.ImageFileInfo.Id;
                        branchEntry.DestinationInstructionRelativeAddress = location.relativeStartAddress;

                        // Did we see a Ret1 entry? -> accurate source location info
                        if(lastRet1Entry != null)
                        {
                            branchEntry.SourceImageId = lastRet1Entry.Value.imageFileInfo.Id;
                            branchEntry.SourceInstructionRelativeAddress = lastRet1Entry.Value.address;

                            lastRet1Entry = null;
                        }
                        else
                        {
                            branchEntry.SourceImageId = _externalFunctionsImageId;
                            branchEntry.SourceInstructionRelativeAddress = _catchAllExternalFunctionAddress;
                        }

                        branchEntry.Store(traceFileWriter);

                        break;
                    }

                    case 'j':
                    {
                        // Parse line
                        var scriptIdPart = NextSplit(ref lineParts, separator);
                        var sourcePart = NextSplit(ref lineParts, separator);
                        var destinationPart = NextSplit(ref lineParts, separator);

                        int scriptId = ParseInt32NotSigned(scriptIdPart);

                        // Resolve code locations
                        var source = ResolveLineInfo(scriptId, sourcePart);
                        var destination = ResolveLineInfo(scriptId, destinationPart);

                        // Produce MAP entries
                        tryAddRequestedMapEntry((source.imageData.ImageFileInfo.Id, source.relativeStartAddress), null);
                        tryAddRequestedMapEntry((destination.imageData.ImageFileInfo.Id, destination.relativeStartAddress), null);

                        // Do not trace branches in prefix mode
                        if(_firstTestcase)
                            break;

                        // Create branch entry
                        branchEntry.BranchType = Branch.BranchTypes.Jump;
                        branchEntry.Taken = true;
                        branchEntry.SourceImageId = source.imageData.ImageFileInfo.Id;
                        branchEntry.SourceInstructionRelativeAddress = source.relativeStartAddress;
                        branchEntry.DestinationImageId = destination.imageData.ImageFileInfo.Id;
                        branchEntry.DestinationInstructionRelativeAddress = destination.relativeStartAddress;
                        branchEntry.Store(traceFileWriter);

                        break;
                    }

                    case 'm':
                    {
                        // Parse line
                        var accessType = NextSplit(ref lineParts, separator);
                        var scriptIdPart = NextSplit(ref lineParts, separator);
                        var locationPart = NextSplit(ref lineParts, separator);
                        var objectIdPart = NextSplit(ref lineParts, separator);
                        var offsetPart = NextSplit(ref lineParts, separator);

                        // Resolve code locations
                        int scriptId = ParseInt32NotSigned(scriptIdPart);
                        var location = ResolveLineInfo(scriptId, locationPart);

                        // Produce MAP entries
                        tryAddRequestedMapEntry((location.imageData.ImageFileInfo.Id, location.relativeStartAddress), null);

                        // Extract access data
                        int objectId = ParseInt32NotSigned(objectIdPart);
                        string offset = new string(offsetPart);

                        // Did we already encounter this object?
                        uint offsetRelativeAddress;
                        if(!heapObjects.TryGetValue(objectId, out var objectData))
                        {
                            objectData = new HeapObjectData { NextPropertyAddress = 0x100000 };
                            heapObjects.Add(objectId, objectData);

                            heapAllocationEntry.Id = objectId;
                            heapAllocationEntry.Address = nextHeapAllocationAddress;
                            heapAllocationEntry.Size = 2 * heapAllocationChunkSize;
                            heapAllocationEntry.Store(traceFileWriter);

                            nextHeapAllocationAddress += 2 * heapAllocationChunkSize;

                            // Create entry for current access
                            // Numeric index, or named property?
                            offsetRelativeAddress = uint.TryParse(offset, out uint offsetInt)
                                ? offsetInt
                                : objectData.NextPropertyAddress++;
                            objectData.PropertyAddressMapping.TryAdd(offset, offsetRelativeAddress);
                        }
                        else
                        {
                            // Did we already encounter this offset?
                            offsetRelativeAddress = objectData.PropertyAddressMapping.GetOrAdd(offset, static (offsetParam, objectDataParam) =>
                            {
                                // No, create new entry

                                // Numeric index?
                                if(uint.TryParse(offsetParam, out uint offsetInt))
                                    return offsetInt;

                                // Named property
                                return Interlocked.Increment(ref objectDataParam.NextPropertyAddress);
                            }, objectData);
                        }

                        // Do not trace memory accesses in prefix mode
                        if(_firstTestcase)
                            break;

                        // Create memory access
                        heapMemoryAccessEntry.InstructionImageId = location.imageData.ImageFileInfo.Id;
                        heapMemoryAccessEntry.InstructionRelativeAddress = location.relativeStartAddress;
                        heapMemoryAccessEntry.HeapAllocationBlockId = objectId;
                        heapMemoryAccessEntry.MemoryRelativeAddress = offsetRelativeAddress;
                        heapMemoryAccessEntry.Size = 1;
                        heapMemoryAccessEntry.IsWrite = accessType == "w";
                        heapMemoryAccessEntry.Store(traceFileWriter);

                        break;
                    }

                    /*
                    case 'Y':
                    {
                        // TODO yield/yield resume
                    }
                    */

                    default:
                    {
                        throw new Exception($"{logPrefix} Could not parse line: {line}");
                    }
                }
            }
        }

        if(_firstTestcase)
        {
            _prefixNextHeapAllocationAddress = nextHeapAllocationAddress;
            _prefixHeapObjects = heapObjects;
            _prefixCompressedLinesLookup = compressedLinesLookup;
        }
    }

    /// <summary>
    /// Resolves a line/column number info into an image and a pair of image-relative start/end addresses. 
    /// </summary>
    /// <param name="scriptFileId">ID of the script file containing these lines.</param>
    /// <param name="lineInfo">
    /// Line number information.
    ///
    /// Supported formats:
    /// - startLine:startColumn:endLine:endColumn
    /// - functionName:constructor
    /// </param>
    private (ImageData imageData, uint relativeStartAddress, uint relativeEndAddress) ResolveLineInfo(int? scriptFileId, ReadOnlySpan<char> lineInfo)
    {
        // We use line info as key for caching known addresses
        string lineInfoString = new string(lineInfo);

        // Try to read existing address data, or generate new one if not known yet
        var imageData = _imageData[scriptFileId ?? _externalFunctionsImageId];
        (uint start, uint end) addressData;
        if(_firstTestcase)
        {
            if(!imageData.RelativeAddressLookupPrefix!.TryGetValue(lineInfoString, out addressData))
            {
                addressData = GenerateAddressLookupEntry(lineInfoString, (this, scriptFileId));
                imageData.RelativeAddressLookupPrefix!.Add(lineInfoString, addressData);
            }
        }
        else
            addressData = imageData.RelativeAddressLookup!.GetOrAdd(lineInfoString, GenerateAddressLookupEntry, (this, scriptFileId));

        return (imageData, addressData.start, addressData.end);
    }

    /// <summary>
    /// Generates a new entry for the relative address lookup.
    /// </summary>
    /// <param name="lineInfoString">Line info.</param>
    /// <param name="args">Arguments.</param>
    /// <returns>Relative start and end address.</returns>
    /// <remarks>
    /// This method is static to avoid an implicit capture of the <see cref="JsTracePreprocessor"/> instance, causing a heap allocation.
    /// </remarks>
    private static (uint start, uint end) GenerateAddressLookupEntry(string lineInfoString, (JsTracePreprocessor instance, int? scriptFileId) args)
    {
        const char separator = ':';

        // Split
        var lineInfoStringSpan = lineInfoString.AsSpan(); // We can't capture the lineInfo Span directly

        // Unknown script / external function?
        bool isExternal = args.scriptFileId == null;
        if(isExternal)
        {
            // Get address of function, or generate a new one if it does not yet exist
            // Necessary locking is done by the underlying concurrent dictionary (if not in prefix mode)
            string functionName = lineInfoString;
            if(args.instance._firstTestcase)
            {
                if(!args.instance._externalFunctionAddressesPrefix!.TryGetValue(functionName, out uint externalFunctionAddress))
                {
                    externalFunctionAddress = ++args.instance._currentExternalFunctionAddress;
                    args.instance._externalFunctionAddressesPrefix.Add(functionName, externalFunctionAddress);
                }

                return (externalFunctionAddress, externalFunctionAddress);
            }
            else
            {
                uint externalFunctionAddress = args.instance._externalFunctionAddresses!.GetOrAdd(
                    functionName,
                    _ => Interlocked.Increment(ref args.instance._currentExternalFunctionAddress)
                );

                return (externalFunctionAddress, externalFunctionAddress);
            }
        }

        // Split
        var part1 = NextSplit(ref lineInfoStringSpan, separator);
        var part2 = NextSplit(ref lineInfoStringSpan, separator);
        var part3 = NextSplit(ref lineInfoStringSpan, separator);
        var part4 = NextSplit(ref lineInfoStringSpan, separator);

        // Normal function
        uint startLine = ParseUInt32(part1);
        uint startColumn = ParseUInt32(part2);
        uint endLine = ParseUInt32(part3);
        uint endColumn = ParseUInt32(part4);
        uint startAddress = (startLine << args.instance._columnsBits) | startColumn;
        uint endAddress = (endLine << args.instance._columnsBits) | endColumn;

        return (startAddress, endAddress);
    }

    protected override Task InitAsync(MappingNode? moduleOptions)
    {
        if(moduleOptions == null)
            throw new ConfigurationException("Missing module configuration.");

        string mapDirectoryPath = moduleOptions.GetChildNodeOrDefault("map-directory")?.AsString() ?? throw new ConfigurationException("Missing MAP file directory.");
        _mapDirectory = Directory.CreateDirectory(mapDirectoryPath);

        string? outputDirectoryPath = moduleOptions.GetChildNodeOrDefault("output-directory")?.AsString();
        if(outputDirectoryPath != null)
            _outputDirectory = Directory.CreateDirectory(outputDirectoryPath);

        _storeTraces = moduleOptions.GetChildNodeOrDefault("store-traces")?.AsBoolean() ?? false;
        if(_storeTraces && outputDirectoryPath == null)
            throw new ConfigurationException("Missing output directory for preprocessed traces.");

        int? columnsBitsValue = moduleOptions.GetChildNodeOrDefault("columns-bits")?.AsInteger();
        if(columnsBitsValue != null)
            _columnsBits = columnsBitsValue.Value;

        // Sanity check
        if(_columnsBits > 30)
            throw new ConfigurationException("The number of columns bits must not exceed 30, as there must be space left for encoding line numbers.");

        // Compute mask for columns
        _columnMask = (1u << _columnsBits) - 1;

        return Task.CompletedTask;
    }

    public override async Task UnInitAsync()
    {
        List<char> replaceChars = Path.GetInvalidPathChars().Append('/').Append('\\').Append('.').ToList();

        // Save MAP data
        if(_requestedMapEntries == null)
            return;
        Dictionary<int, List<uint>> requestedMapEntriesPerImage = _requestedMapEntries
            .GroupBy(m => m.Key.imageId)
            .ToDictionary(m => m.Key, m => m
                .Select(n => n.Key.relativeAddress)
                .OrderBy(n => n)
                .ToList()
            );
        var sortedFunctionNameLookups = _imageData.ToDictionary(i => i.ImageFileInfo.Id, i => new SortedList<(uint start, uint end), string>(i.FunctionNameLookup ?? new()));
        foreach(var imageData in _imageData)
        {
            int imageFileId = imageData.ImageFileInfo.Id;

            string mapFileName = Path.Join(_mapDirectory.FullName, replaceChars.Aggregate(imageData.ImageFileInfo.Name, (current, invalidPathChar) => current.Replace(invalidPathChar, '_')) + ".map");
            await using var mapFileWriter = new StreamWriter(File.Open(mapFileName, FileMode.Create));
            
            await mapFileWriter.WriteLineAsync(imageData.ImageFileInfo.Name);

            // Create MAP entries
            if(!requestedMapEntriesPerImage.TryGetValue(imageFileId, out var requestedMapEntries))
                continue;
            var functionNameLookup = sortedFunctionNameLookups[imageFileId];
            foreach(uint relativeAddress in requestedMapEntries)
            {
                string name = functionNameLookup.LastOrDefault(
                    functionData => functionData.Key.start <= relativeAddress && relativeAddress <= functionData.Key.end,
                    new KeyValuePair<(uint start, uint end), string>(default, "?")
                ).Value;

                // Handle [extern] functions separately
                if(imageFileId == _externalFunctionsImage.Id)
                    await mapFileWriter.WriteLineAsync($"{relativeAddress:x8}\t{name}");
                else
                {
                    // Extract column/line data from address
                    int column = (int)(relativeAddress & _columnMask);
                    int line = (int)(relativeAddress >> _columnsBits);

                    await mapFileWriter.WriteLineAsync($"{relativeAddress:x8}\t{name}:{line}:{column}");
                }
            }
        }
    }

    /// <summary>
    /// Looks for the separator and returns the next string part before it.
    /// Updates the given string span to point to the remaining string.
    /// </summary>
    /// <param name="str">String to split.</param>
    /// <param name="separator">Split character.</param>
    /// <returns></returns>
    private static ReadOnlySpan<char> NextSplit(ref ReadOnlySpan<char> str, char separator)
    {
        // Look for separator
        for(int i = 0; i < str.Length; ++i)
        {
            if(str[i] == separator)
            {
                // Get part
                var part = str[..i];
                str = str[(i + 1)..];
                return part;
            }
        }

        // Not found, return entire remaining string
        var tmp = str;
        str = ReadOnlySpan<char>.Empty;
        return tmp;
    }

    /// <summary>
    /// Parses an integer from the given string.
    /// This method assumes that the integer is valid and _not_ signed.
    /// </summary>
    /// <param name="str">String to parse.</param>
    /// <returns></returns>
    private static int ParseInt32NotSigned(ReadOnlySpan<char> str)
    {
        return unchecked((int)ParseUInt32(str));
    }

    /// <summary>
    /// Parses an unsigned integer from the given string.
    /// This method assumes that the integer is valid and not signed.
    /// </summary>
    /// <param name="str">String to parse.</param>
    /// <returns></returns>
    private static unsafe uint ParseUInt32(ReadOnlySpan<char> str)
    {
        uint result = 0;
        fixed(char* strBeginPtr = str)
        {
            char* strEndPtr = strBeginPtr + str.Length;
            char* strPtr = strBeginPtr;
            while(strPtr != strEndPtr)
            {
                result = result * 10 + unchecked((uint)(*(strPtr++) - '0'));
            }
        }

        return result;
    }

    private class HeapObjectData
    {
        public uint NextPropertyAddress;

        public ConcurrentDictionary<string, uint> PropertyAddressMapping { get; } = new();
    }

    private class ImageData(TracePrefixFile.ImageFileInfo imageFileInfo)
    {
        /// <summary>
        /// Image file info.
        /// </summary>
        public TracePrefixFile.ImageFileInfo ImageFileInfo { get; } = imageFileInfo;

        /// <summary>
        /// Lookup for all encoded relative addresses. Indexed by encoding ("script.js:1:2:1:3").
        /// </summary>
        public ConcurrentDictionary<string, (uint start, uint end)>? RelativeAddressLookup { get; set; }

        /// <summary>
        /// Lookup for all encoded relative addresses. Indexed by encoding ("script.js:1:2:1:3").
        /// 
        /// This variable used by the prefix preprocessing step exclusively, the data is copied to <see cref="RelativeAddressLookup"/> afterwards.
        /// </summary>
        public Dictionary<string, (uint start, uint end)>? RelativeAddressLookupPrefix { get; set; } = new();

        /// <summary>
        /// Maps encoded start and end addresses to function names.
        /// </summary>
        public ConcurrentDictionary<(uint start, uint end), string>? FunctionNameLookup { get; set; }

        /// <summary>
        /// Maps encoded start and end addresses to function names.
        /// 
        /// This variable used by the prefix preprocessing step exclusively, the data is copied to <see cref="FunctionNameLookup"/> afterwards.
        /// </summary>
        public Dictionary<(uint start, uint end), string>? FunctionNameLookupPrefix { get; set; } = new();
    }
}