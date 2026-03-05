using Microwalk.FrameworkBase.Utilities;

namespace Microwalk.FrameworkBase.TraceFormat.TraceEntryTypes;

/// <summary>
/// A souce info entry.
/// </summary>
public class SourceInfo : ITraceEntry
{
    public TraceEntryTypes EntryType => TraceEntryTypes.StackAllocation;
    // TODO: Figure out how to handle variable string sizes or if it's even needed
    public const int EntrySize = 1 + 2 + 8 + 32;

    public void FromReader(IFastBinaryReader reader)
    {
        ColNum = reader.ReadUInt16();
        LineNum = reader.ReadUInt64();
        SourceName = reader.ReadUInt64();
    }

    public void Store(IFastBinaryWriter writer)
    {
        writer.WriteByte((byte)TraceEntryTypes.SourceInfo);
        writer.WriteUInt16(ColNum);
        writer.WriteUInt64(LineNum);
        writer.WriteUInt64(SourceName);
    }
    /// <summary>
    /// The column number which this entry belongs to.
    /// </summary>
    public ushort ColNum { get; set; }

    /// <summary>
    /// The line number which this entry belongs to.
    /// </summary>
    public ulong LineNum { get; set; }

    /// <summary>
    /// The name of the file which this entry was extracted from.
    /// </summary>
    public ulong SourceName { get; set; }
}
