using System;
using Microwalk.FrameworkBase.Utilities;

namespace Microwalk.FrameworkBase.TraceFormat.TraceEntryTypes;

/// <summary>
/// A source info entry.
/// </summary>
public record SourceInfo : ITraceEntry
{
    public TraceEntryTypes EntryType => TraceEntryTypes.SourceInfo;

    public const int EntrySize = 1 + 2 + 8 + 8;

    // Parameter-less default constructor 
    public SourceInfo() 
    { 
        ColNum = 0;
        LineNum = 0;
        SourceName = 0;
    }

    public virtual bool Equals(SourceInfo? other)
    {
        if (other is null) return false;
        
        return ColNum == other.ColNum &&
               LineNum == other.LineNum &&
               SourceName == other.SourceName;
    }
    public override int GetHashCode()
    {
        return HashCode.Combine(ColNum, LineNum, SourceName);
    } 

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
