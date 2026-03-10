using Microwalk.FrameworkBase.Utilities;

namespace Microwalk.FrameworkBase.TraceFormat.TraceEntryTypes;

/// <summary>
/// A source info entry.
/// </summary>
public class SourceInfo : ITraceEntry
{
    public TraceEntryTypes EntryType => TraceEntryTypes.SourceInfo;
    public const int EntrySize = 1 + 4 + 2 + 8 + 8;

    public void FromReader(IFastBinaryReader reader)
    {
        Id = reader.ReadInt32();
        ColNum = reader.ReadUInt16();
        LineNum = reader.ReadUInt64();
        SourceName = reader.ReadUInt64();
    }

    public void Store(IFastBinaryWriter writer)
    {
        writer.WriteByte((byte)TraceEntryTypes.SourceInfo);
        writer.WriteInt32(Id);
        writer.WriteUInt16(ColNum);
        writer.WriteUInt64(LineNum);
        writer.WriteUInt64(SourceName);
    }

    /// <summary>
    /// The ID of the allocated block.
    /// </summary>
    public int Id { get; set; }

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
