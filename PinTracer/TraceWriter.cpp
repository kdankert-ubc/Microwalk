/* INCLUDES */
#include "TraceWriter.h"
#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <utility>

#include "FilterEntry.h"

/* GLOBALS */
std::vector<FilterEntry> filter;

/* STATIC VARIABLES */

std::map<ADDRINT, std::string> TraceWriter::_alias;
bool TraceWriter::_prefixMode;
std::ofstream TraceWriter::_prefixDataFileStream;
std::ofstream TraceWriter::_aliasFileStream("alias.txt");

bool TraceWriter::_sawFirstReturn;

/* TYPES */

TraceWriter::TraceWriter(const std::string& filenamePrefix)
{
    // Remember prefix
    _outputFilenamePrefix = filenamePrefix;

    // Open prefix output file
	std::string filename = filenamePrefix + "prefix.trace";
    OpenOutputFile(filename);
}

TraceWriter::~TraceWriter()
{
    // Close file stream
    _aliasFileStream.close();
    _outputFileStream.close();
}

void TraceWriter::InitPrefixMode(const std::string& filenamePrefix)
{
    // Start trace prefix mode
    _prefixMode = true;
    _sawFirstReturn = true;

    // Open prefix metadata output file
    _prefixDataFileStream.exceptions(std::ofstream::failbit | std::ofstream::badbit);
	std::string prefixDataFilename = filenamePrefix + "prefix_data.txt";
    _prefixDataFileStream.open(prefixDataFilename.c_str(), std::ofstream::out | std::ofstream::trunc);
    if(!_prefixDataFileStream)
    {
        std::cerr << "Error: Could not open prefix metadata output file '" << prefixDataFilename << "'." << std::endl;
        exit(1);
    }
    std::cerr << "Trace prefix mode started" << std::endl;
}

TraceEntry* TraceWriter::Begin()
{
    return _entries;
}

TraceEntry* TraceWriter::End()
{
    return &_entries[ENTRY_BUFFER_SIZE];
}

void TraceWriter::OpenOutputFile(std::string& filename)
{
    // Open file for writing
    _outputFileStream.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    _currentOutputFilename = filename;
    _outputFileStream.open(_currentOutputFilename.c_str(), std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);
    if(!_outputFileStream)
    {
        std::cerr << "Error: Could not open output file '" << _currentOutputFilename << "'." << std::endl;
        exit(1);
    }
}

void TraceWriter::WriteBufferToFile(TraceEntry* end)
{
    // Write buffer contents
    if(_testcaseId != -1 || _prefixMode)
        _outputFileStream.write(reinterpret_cast<char*>(_entries), static_cast<std::streamsize>(reinterpret_cast<ADDRINT>(end) - reinterpret_cast<ADDRINT>(_entries)));
}

void TraceWriter::TestcaseStart(int testcaseId, TraceEntry* nextEntry)
{
    // Exit prefix mode if necessary
    if(_prefixMode)
        TestcaseEnd(nextEntry);

    // Remember new testcase ID
    _testcaseId = testcaseId;
    _sawFirstReturn = false;

    // Open file for writing
    std::stringstream filenameStream;
    filenameStream << _outputFilenamePrefix << "t" << std::dec << _testcaseId << ".trace";
	std::string filename = filenameStream.str();
    OpenOutputFile(filename);
    std::cerr << "Switched to testcase #" << std::dec << _testcaseId << std::endl;
}

void TraceWriter::TestcaseEnd(TraceEntry* nextEntry)
{
    // Save remaining trace data
    if(nextEntry != _entries)
        WriteBufferToFile(nextEntry);

    // Close file handle and reset flags
    _outputFileStream.close();
    _outputFileStream.clear();

    // Exit prefix mode if necessary
    if(_prefixMode)
    {
        _prefixDataFileStream.close();
        _prefixMode = false;
        std::cerr << "Trace prefix mode ended" << std::endl;
    }
    else
    {
        // Notify caller that the trace file is complete
		std::cout << "t\t" << _currentOutputFilename << std::endl;
    }

    // Disable tracing until next test case starts
    _testcaseId = -1;
}

void TraceWriter::WriteImageLoadData(int interesting, uint64_t startAddress, uint64_t endAddress, std::string& name)
{
    // Prefix mode active?
    if(!_prefixMode)
    {
        std::cerr << "Image load ignored: " << name << std::endl;
        return;
    }

    // Write image data
    _prefixDataFileStream << "i\t" << interesting << "\t" << std::hex << startAddress << "\t" << std::hex << endAddress << "\t" << name << std::endl;
}

bool TraceWriter::IsWhitelisted(TraceEntryTypes type, ADDRINT instr, ADDRINT addr, UINT8 *flag)
{
    if (filter.size() == 0)
        return true;

    for (size_t i = 0; i < filter.size(); ++i) {
        FilterEntry &entry = filter[i];

        if ((entry.originStart == 0 || entry.originEnd == 0) && (entry.targetStart == 0 || entry.targetEnd == 0))
            continue;

        bool acc = true;
        if (entry.originStart && entry.originEnd)
            acc &= instr >= (ADDRINT) entry.originStart && instr <= (ADDRINT) entry.originEnd;
        if (entry.targetStart && entry.targetEnd)
            acc &= addr >= (ADDRINT) entry.targetStart && addr <= (ADDRINT) entry.targetEnd;

        if (!acc)
            continue;

        if (type == TraceEntryTypes::MemoryRead && FilterTypeMatch(FilterTypeDataAccess | FilterTypeRead, entry.type)) {
            // std::cerr << "Memory read at address " << std::hex << addr << std::endl;
            return entry.type & FilterTypeWhiteList;
        }

        if (type == TraceEntryTypes::MemoryWrite && FilterTypeMatch(FilterTypeDataAccess | FilterTypeWrite, entry.type)) {
            // std::cerr << "Memory write at address " << std::hex << addr << std::endl;
            return entry.type & FilterTypeWhiteList;
        }

        if (flag == nullptr) {
            continue;
        }

        if (type == TraceEntryTypes::Branch && FilterTypeMatch(FilterTypeControlFlow | FilterTypeJump, entry.type) && (*flag & (UINT8) TraceEntryFlags::BranchTypeReturn) == (UINT8) TraceEntryFlags::BranchTypeJump) {
            // std::cerr << "Jump to address " << std::hex << addr << std::endl;
            return entry.type & FilterTypeWhiteList;
        }

        if (type == TraceEntryTypes::Branch && FilterTypeMatch(FilterTypeControlFlow | FilterTypeCall, entry.type) && (*flag & (UINT8) TraceEntryFlags::BranchTypeReturn) == (UINT8) TraceEntryFlags::BranchTypeCall) {
            // std::cerr << "Call to address " << std::hex << addr << std::endl;
            if (entry.type & FilterTypeLinearize)
                *flag ^= (UINT8) TraceEntryFlags::BranchTypeCall ^ (UINT8) TraceEntryFlags::BranchTypeJump;
            return entry.type & FilterTypeWhiteList;
        }

        if (type == TraceEntryTypes::Branch && FilterTypeMatch(FilterTypeControlFlow | FilterTypeCall, entry.type) && (*flag & (UINT8) TraceEntryFlags::BranchTypeReturn) == (UINT8) TraceEntryFlags::BranchTypeReturn) {
            // std::cerr << "Return from address " << std::hex << addr << std::endl;
            return entry.type & FilterTypeWhiteList;
        }
    }

    return false;
}

TraceEntry* TraceWriter::CheckBufferAndStore(TraceWriter *traceWriter, TraceEntry* nextEntry)
{
    if(traceWriter == nullptr || nextEntry == nullptr)
        return nullptr;

    // Entry list full?
    if(nextEntry == traceWriter->End())
    {
        // Write entries to file, restart writing entries at the list begin
        traceWriter->WriteBufferToFile(traceWriter->End());
        return traceWriter->Begin();
    }

    // Nothing to do here
    return nextEntry;
}

TraceEntry* TraceWriter::InsertMemoryReadEntry(TraceWriter *traceWriter, TraceEntry* nextEntry, ADDRINT instructionAddress, ADDRINT memoryAddress, UINT32 size)
{
    if (!IsWhitelisted(TraceEntryTypes::MemoryRead, instructionAddress, memoryAddress, nullptr))
        return nextEntry;

    // Create entry
    nextEntry->Type = TraceEntryTypes::MemoryRead;
    nextEntry->Param0 = size;
    nextEntry->Param1 = instructionAddress;
    nextEntry->Param2 = memoryAddress;

    return CheckBufferAndStore(traceWriter, nextEntry + 1);
}

TraceEntry* TraceWriter::InsertMemoryWriteEntry(TraceWriter *traceWriter, TraceEntry* nextEntry, ADDRINT instructionAddress, ADDRINT memoryAddress, UINT32 size)
{
    if (!IsWhitelisted(TraceEntryTypes::MemoryWrite, instructionAddress, memoryAddress, nullptr))
        return nextEntry;

    // Create entry
    nextEntry->Type = TraceEntryTypes::MemoryWrite;
    nextEntry->Param0 = size;
    nextEntry->Param1 = instructionAddress;
    nextEntry->Param2 = memoryAddress;

    return CheckBufferAndStore(traceWriter, nextEntry + 1);
}

TraceEntry* TraceWriter::InsertHeapAllocSizeParameterEntry(TraceWriter *traceWriter, TraceEntry* nextEntry, UINT64 size)
{
    // Check whether given entry pointer is valid (we might be in a non-instrumented thread)
    if(nextEntry == nullptr)
        return nextEntry;

    // Create entry
    nextEntry->Type = TraceEntryTypes::HeapAllocSizeParameter;
    nextEntry->Param1 = size;

    return CheckBufferAndStore(traceWriter, nextEntry + 1);
}

TraceEntry* TraceWriter::InsertCallocSizeParameterEntry(TraceWriter *traceWriter, TraceEntry* nextEntry, UINT64 count, UINT64 size)
{
    return InsertHeapAllocSizeParameterEntry(traceWriter, nextEntry, count * size);
}

TraceEntry* TraceWriter::InsertHeapAllocAddressReturnEntry(TraceWriter *traceWriter, TraceEntry* nextEntry, ADDRINT memoryAddress)
{
    // Check whether given entry pointer is valid (we might be in a non-instrumented thread)
    if(nextEntry == nullptr)
        return nextEntry;

    // Create entry
    nextEntry->Type = TraceEntryTypes::HeapAllocAddressReturn;
    nextEntry->Param2 = memoryAddress;

    return CheckBufferAndStore(traceWriter, nextEntry + 1);
}

TraceEntry* TraceWriter::InsertHeapFreeAddressParameterEntry(TraceWriter *traceWriter, TraceEntry* nextEntry, ADDRINT memoryAddress)
{
    // Check whether given entry pointer is valid (we might be in a non-instrumented thread)
    if(nextEntry == nullptr)
        return nextEntry;

    // Create entry
    nextEntry->Type = TraceEntryTypes::HeapFreeAddressParameter;
    nextEntry->Param2 = memoryAddress;

    return CheckBufferAndStore(traceWriter, nextEntry + 1);
}

TraceEntry* TraceWriter::InsertStackPointerModificationEntry(TraceWriter *traceWriter, TraceEntry* nextEntry, ADDRINT instructionAddress, ADDRINT newStackPointer, UINT8 flags)
{
    // Create entry
    nextEntry->Type = TraceEntryTypes::StackPointerModification;
    nextEntry->Flag = flags;
    nextEntry->Param1 = instructionAddress;
    nextEntry->Param2 = newStackPointer;

    return CheckBufferAndStore(traceWriter, nextEntry + 1);
}

TraceEntry* TraceWriter::InsertBranchEntry(TraceWriter *traceWriter, TraceEntry* nextEntry, ADDRINT sourceAddress, ADDRINT targetAddress, UINT8 taken, UINT8 type)
{
    if (!IsWhitelisted(TraceEntryTypes::Branch, sourceAddress, targetAddress, &type))
        return nextEntry;

    // Create entry
    nextEntry->Type = TraceEntryTypes::Branch;
    nextEntry->Param1 = sourceAddress;
    nextEntry->Param2 = targetAddress;
    nextEntry->Flag = static_cast<UINT8>(type) | static_cast<UINT8>(taken == 0 ? TraceEntryFlags::BranchNotTaken : TraceEntryFlags::BranchTaken);

    return CheckBufferAndStore(traceWriter, nextEntry + 1);
}

TraceEntry* TraceWriter::InsertRetBranchEntry(TraceWriter *traceWriter, TraceEntry* nextEntry, ADDRINT sourceAddress, ADDRINT targetAddress)
{
    // Skip the very first return after testcase begin (else we get an invalid call stack)
    if(!_sawFirstReturn)
    {
        _sawFirstReturn = true;
        return nextEntry;
    }

    // Create entry
    return InsertBranchEntry(traceWriter, nextEntry, sourceAddress, targetAddress, true, static_cast<UINT8>(TraceEntryFlags::BranchTypeReturn));
}

TraceEntry* TraceWriter::InsertStackPointerInfoEntry(TraceWriter *traceWriter, TraceEntry* nextEntry, ADDRINT stackPointerMin, ADDRINT stackPointerMax)
{
    // Create entry
    nextEntry->Type = TraceEntryTypes::StackPointerInfo;
    nextEntry->Param1 = stackPointerMin;
	nextEntry->Param2 = stackPointerMax;

    return CheckBufferAndStore(traceWriter, nextEntry + 1);
}

ImageData::ImageData(bool interesting, std::string name, UINT64 startAddress, UINT64 endAddress)
{
    _interesting = interesting;
    _name = std::move(name);
    _startAddress = startAddress;
    _endAddress = endAddress;
}

bool ImageData::ContainsBasicBlock(BBL basicBlock) const
{
    // Check start address
    return _startAddress <= INS_Address(BBL_InsHead(basicBlock)) && INS_Address(BBL_InsTail(basicBlock)) <= _endAddress;
}

bool ImageData::IsInteresting() const
{
    return _interesting;
}

void TraceWriter::AddAlias(ADDRINT addr, char *name)
{
    bool inserted = _alias.insert(std::pair<ADDRINT, std::string>(addr, name)).second;
    if (!inserted) {
        return;
    }

    PIN_LockClient();
    IMG img = IMG_FindByAddress(addr);
    PIN_UnlockClient();
    if (IMG_Valid(img)) {
        _aliasFileStream << std::hex << std::setw(8) << std::setfill('0') << (addr - IMG_LowAddress(img)) << " " << name << std::endl;
    }
}
