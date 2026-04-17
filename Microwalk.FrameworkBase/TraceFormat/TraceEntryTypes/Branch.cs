using Microwalk.FrameworkBase.Utilities;

namespace Microwalk.FrameworkBase.TraceFormat.TraceEntryTypes;

/// <summary>
/// A code branch.
/// </summary>
public class Branch : ITraceEntry
{
    public TraceEntryTypes EntryType => TraceEntryTypes.Branch;
    public const int EntrySize = 1 + 4 + 4 + 4 + 4 + 1 + 2 + 8 + 8 + 1;

    public void FromReader(IFastBinaryReader reader)
    {
        Source = new SourceInfo();
        SourceImageId = reader.ReadInt32();
        SourceInstructionRelativeAddress = reader.ReadUInt32();
        DestinationImageId = reader.ReadInt32();
        DestinationInstructionRelativeAddress = reader.ReadUInt32();
        Taken = reader.ReadBoolean();
        Source.ColNum = reader.ReadUInt16();
        Source.LineNum = reader.ReadUInt64();
        Source.SourceName = reader.ReadUInt64();
        BranchType = (BranchTypes)reader.ReadByte();
    }

    public void Store(IFastBinaryWriter writer)
    {
        writer.WriteByte((byte)TraceEntryTypes.Branch);
        writer.WriteInt32(SourceImageId);
        writer.WriteUInt32(SourceInstructionRelativeAddress);
        writer.WriteInt32(DestinationImageId);
        writer.WriteUInt32(DestinationInstructionRelativeAddress);
        writer.WriteBoolean(Taken);
        writer.WriteUInt16(Source.ColNum);
        writer.WriteUInt64(Source.LineNum);
        writer.WriteUInt64(Source.SourceName);
        writer.WriteByte((byte)BranchType);
    }

    /// <summary>
    ///  The image ID of the source instruction.
    /// </summary>
    public int SourceImageId { get; set; }

    /// <summary>
    /// The address of the source instruction, relative to the image start address.
    /// </summary>
    public uint SourceInstructionRelativeAddress { get; set; }

    /// <summary>
    /// The image ID of the destination instruction.
    /// </summary>
    public int DestinationImageId { get; set; }

    /// <summary>
    /// The address of the destination instruction, relative to the image start address.
    /// </summary>
    public uint DestinationInstructionRelativeAddress { get; set; }

    /// <summary>
    /// Tells whether the branch was taken.
    /// </summary>
    public bool Taken { get; set; }

    /// <summary>
    /// The type of the branching instruction.
    /// </summary>
    public BranchTypes BranchType { get; set; }

    /// <summary>
    /// The source info associated with this branching instruction.
    /// </summary>
    public SourceInfo Source { get; set; }

    /// <summary>
    /// The type of the branching instruction.
    /// </summary>
    public enum BranchTypes : byte
    {
        Jump = 0,
        Call = 1,
        Return = 2
    }
}