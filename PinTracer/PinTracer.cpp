#include "FilterEntry.h"
#include <iostream>
#include <string>
#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"
/*
IMPORTANT: The instrumented program or one of its dependencies MUST contain (named) "malloc" and "free" functions.
To get meaningful outputs, make sure that these functions are called with "call".
*/


/* INCLUDES */
#include "TraceWriter.h"
#include "Utilities.h"
#include "CpuOverride.h"

// Feature flag for legacy allocation function return tracking.
// Sometimes the compiler replaces tail calls by jump instructions, tripping Pin's IPOINT_AFTER function end detection, leading to missing allocation address returns.
//#define USE_LEGACY_ALLOC_RETURN_TRACKING


/* GLOBAL VARIABLES */

// The output file command line option.
KNOB<std::string> KnobOutputFilePrefix(KNOB_MODE_WRITEONCE, "pintool", "o", "out", "specify file name/path prefix for trace output");

// The names of interesting images, separated by semicolons.
KNOB<std::string> KnobInterestingImageList(KNOB_MODE_WRITEONCE, "pintool", "i", ".exe", "specify list of interesting images, separated by semicolons");

// The desired CPU feature level.
KNOB<int> KnobCpuFeatureLevel(KNOB_MODE_WRITEONCE, "pintool", "c", "0", "specify desired CPU model: 0 = Default, 1 = Pentium3, 2 = Merom, 3 = Westmere, 4 = Ivybridge (your own CPU should form a superset of the selected option)");

// Constant random number generator value.
// Magic default value is 0xBADBADBADBADBAD (Pin does not provide an API to check whether parameter is actually in the command line).
KNOB<UINT64> KnobFixedRandomNumbers(KNOB_MODE_WRITEONCE, "pintool", "r", "841534158063459245", "set constant output for RDRAND instruction");

// Enable stack allocation tracking.
KNOB<int> KnobEnableStackAllocationTracking(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "enable stack allocation tracking");

KNOB<std::string> KnobCustomMemoryFunctions(KNOB_MODE_APPEND, "pintool", "m", "", "specify custom memory allocation functions for instrumentation: type:name:a0:a1. type is one of malloc, calloc, realloc, free, and name is the function name, a0:a1 are the index of arguments passed to the custom function that represent the paramaters passed to the libc equivalents. Specifying custom memory functions disables automatic instrumentation of libc memory functions.");

// The names of interesting images, parsed from the command line option.
std::vector<std::string> _interestingImages;

// The trace writer object (per thread).
REG _traceWriterReg;

// The next writable entry buffer position (per thread).
REG _nextBufferEntryReg;

// The end of the entry buffer (per thread).
REG _entryBufferEndReg;

// The EAX input register of a CPUID instruction.
REG _cpuIdEaxInputReg;

// The ECX input register of a CPUID instruction.
REG _cpuIdEcxInputReg;

// Data of loaded images for lookup during trace instrumentation.
std::vector<ImageData*> _images;

// Controls whether RDRAND random numbers are replaced by fixed ones.
bool _useFixedRandomNumber = false;

// Controls whether stack allocation tracking is enabled.
bool _enableStackAllocationTracking = false;

// Tracks whether libc was loaded.
#ifdef WIN32
	bool _libcLoadDetected = true;
#else
	bool _libcLoadDetected = false;
#endif

// The fixed random number to be returned after each RDRAND instruction.
UINT64 _fixedRandomNumber = 0;

// Depth of the allocation call stack.
// 0 is the call stack level of the allocation function itself.
// -1 indicates that allocation tracking is inactive.
int _allocationCallStackDepth = -1;


/* CALLBACK PROTOTYPES */

VOID InstrumentTrace(TRACE trace, [[maybe_unused]] VOID* v);
VOID ThreadStart(THREADID tid, CONTEXT* ctxt, [[maybe_unused]] INT32 flags, [[maybe_unused]] VOID* v);
VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, [[maybe_unused]] INT32 code, [[maybe_unused]] VOID* v);
VOID InstrumentImage(IMG img, [[maybe_unused]] VOID* v);
TraceEntry* TestcaseStart(TraceWriter *traceWriter, TraceEntry* nextEntry, ADDRINT newTestcaseId);
TraceEntry* TestcaseEnd(TraceWriter *traceWriter, TraceEntry* nextEntry);
EXCEPT_HANDLING_RESULT HandlePinToolException([[maybe_unused]] THREADID tid, EXCEPTION_INFO* exceptionInfo,
                                              [[maybe_unused]] PHYSICAL_CONTEXT* physicalContext, [[maybe_unused]] VOID* v);
ADDRINT CheckNextTraceEntryPointerValid(TraceEntry* nextEntry);
VOID StartAllocationTracking(TraceEntry *nextEntry);
VOID TrackAllocationCall();
TraceEntry* TrackAllocationReturn(TraceWriter *traceWriter, TraceEntry *nextEntry, ADDRINT returnValue);
void ChangeRandomNumber(ADDRINT* outputReg);
void SetFilter(FilterEntry* addr, size_t size);
void AddFilter(FilterEntry* entry);
void RemoveFilter(FilterType type, ADDRINT origin, ADDRINT target);
void PrintFilter();
void AddAlias(ADDRINT addr, char *name);

/* FUNCTIONS */

// The main procedure of the tool.
int main(int argc, char* argv[])
{
	// Initialize PIN library
	if(PIN_Init(argc, argv))
	{
		// Print help message if -h(elp) is specified in the command line or the command line is invalid 
		std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
		return -1;
	}

	// Split list of interesting images
	std::stringstream interestingImagesStringStream(KnobInterestingImageList);
	std::string item;
	while(std::getline(interestingImagesStringStream, item, ':'))
		if(!item.empty())
		{
			tolower(item);
			_interestingImages.push_back(item);
		}

	// Create trace entry buffer and all associated variables
    _traceWriterReg = PIN_ClaimToolRegister();
	_nextBufferEntryReg = PIN_ClaimToolRegister();
	_entryBufferEndReg = PIN_ClaimToolRegister();

	// Reserve tool registers for CPUID modification
	_cpuIdEaxInputReg = PIN_ClaimToolRegister();
	_cpuIdEcxInputReg = PIN_ClaimToolRegister();

	// Set model for CPU emulation
	SetEmulatedCpu(KnobCpuFeatureLevel.Value());

	// Check if constant random numbers are desired
	if(KnobFixedRandomNumbers.Value() != static_cast<UINT64>(0xBADBADBADBADBAD))
	{
		_useFixedRandomNumber = true;
		_fixedRandomNumber = KnobFixedRandomNumbers.Value();
		std::cerr << "Using fixed RDRAND output " << _fixedRandomNumber << std::endl;
	}

	// Check if stack allocation tracking is enabled
	if(KnobEnableStackAllocationTracking.Value() != 0)
	{
		_enableStackAllocationTracking = true;
		std::cerr << "Stack allocation tracking is enabled" << std::endl;
	}

	// Initialize prefix mode
	TraceWriter::InitPrefixMode(trim(KnobOutputFilePrefix.Value()));

	// Instrument instructions and routines
	IMG_AddInstrumentFunction(InstrumentImage, nullptr);
	TRACE_AddInstrumentFunction(InstrumentTrace, nullptr);

	// Set thread event handlers
	PIN_AddThreadStartFunction(ThreadStart, nullptr);
	PIN_AddThreadFiniFunction(ThreadFini, nullptr);

	// Handle internal exceptions (for debugging)
	PIN_AddInternalExceptionHandler(HandlePinToolException, nullptr);

	// Load symbols to access function name information
	PIN_InitSymbols();

	// Start the target program
	PIN_StartProgram();
	return 0;
}


/* CALLBACKS */

// [Callback] Instruments memory access instructions.
VOID InstrumentTrace(TRACE trace, [[maybe_unused]] VOID* v)
{
	// Check each instruction in each basic block
	for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		// Before instrumentation check first whether we are in an interesting image
		ImageData* img = nullptr;
		for(ImageData* i : _images)
			if(i->ContainsBasicBlock(bbl))
			{
				img = i;
				break;
			}
		bool interesting;
		if(img == nullptr)
		{
			// Should not happen, since images should have been loaded before they can be instrumented...
			// ...though Pin sometimes executes a few blocks of libc before recording its load
			if(!_libcLoadDetected)
				std::cerr << "Warning: Cannot resolve image of basic block " << std::hex << BBL_Address(bbl) << " - very likely an early loaded part of libc, so this can be safely ignored" << std::endl;
			else
				std::cerr << "Error: Cannot resolve image of basic block " << std::hex << BBL_Address(bbl) << std::endl;

			// The affected blocks are most likely early blocks from libc and are never executed again - so no harm in marking them as 'interesting' just in case
			interesting = true;
		}
		else
		{
			interesting = img->IsInteresting();
		}

		// Run through instructions
		for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			// Ignore everything that uses segment registers (shouldn't be used by relevant software parts)
			// Windows e.g. uses GS for thread local storage
			// We also don't support far jumps/call/returns, so tracing programs which make use of those may lead to interesting behavior 
			// TODO Hint that in documentation
			if(INS_SegmentPrefix(ins))
				continue;

			// Ignore frequent and uninteresting instructions to reduce instrumentation time
			OPCODE opc = INS_Opcode(ins);
			if(opc >= XED_ICLASS_PUSH && opc <= XED_ICLASS_PUSHFQ)
				continue;
			if(opc >= XED_ICLASS_POP && opc <= XED_ICLASS_POPFQ)
				continue;
			if(opc == XED_ICLASS_LEA)
				continue;

			// Change CPUID instruction
			if(opc == XED_ICLASS_CPUID)
			{
				// Save input registers
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(PIN_SetContextReg),
					IARG_CONTEXT,
					IARG_UINT32, _cpuIdEaxInputReg,
					IARG_REG_VALUE, REG_EAX,
					IARG_END);
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(PIN_SetContextReg),
					IARG_CONTEXT,
					IARG_UINT32, _cpuIdEcxInputReg,
					IARG_REG_VALUE, REG_ECX,
					IARG_END);

				// Modify output registers
				INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(ChangeCpuId),
					IARG_REG_VALUE, _cpuIdEaxInputReg,
					IARG_REG_VALUE, _cpuIdEcxInputReg,
					IARG_REG_REFERENCE, REG_EAX,
					IARG_REG_REFERENCE, REG_EBX,
					IARG_REG_REFERENCE, REG_ECX,
					IARG_REG_REFERENCE, REG_EDX,
					IARG_END);

				continue;
			}

			// Overwrite RDRAND instruction
			if(opc == XED_ICLASS_RDRAND && _useFixedRandomNumber)
			{
				// Modify output register
				INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(ChangeRandomNumber),
					IARG_REG_REFERENCE, INS_RegW(ins, 0),
					IARG_END);

				continue;
			}

			// Trace branch instructions (conditional and unconditional)
			if(INS_IsCall(ins) && INS_IsControlFlow(ins))
			{
				// call instructions cannot be instrumented with IPOINT_AFTER, since they do have no fallthrough
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertBranchEntry),
                    IARG_REG_VALUE, _traceWriterReg,
					IARG_REG_VALUE, _nextBufferEntryReg,
					IARG_INST_PTR,
					IARG_BRANCH_TARGET_ADDR,
					IARG_BOOL, 1,
					IARG_UINT32, TraceEntryFlags::BranchTypeCall,
					IARG_RETURN_REGS, _nextBufferEntryReg,
					IARG_END);

				// Store stack pointer value
				if(_enableStackAllocationTracking)
				{
					INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(TraceWriter::InsertStackPointerModificationEntry),
                        IARG_REG_VALUE, _traceWriterReg,
						IARG_REG_VALUE, _nextBufferEntryReg,
						IARG_INST_PTR,
						IARG_REG_VALUE, REG_RSP,
						IARG_UINT32, TraceEntryFlags::StackIsCall,
						IARG_RETURN_REGS, _nextBufferEntryReg,
						IARG_END);
				}

#ifndef USE_LEGACY_ALLOC_RETURN_TRACKING
                // Trace allocation function returns
                INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(TrackAllocationCall),
                    IARG_END);
#endif

				continue;
			}
			if(INS_IsBranch(ins) && INS_IsControlFlow(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertBranchEntry),
                    IARG_REG_VALUE, _traceWriterReg,
					IARG_REG_VALUE, _nextBufferEntryReg,
					IARG_INST_PTR,
					IARG_BRANCH_TARGET_ADDR,
					IARG_BRANCH_TAKEN,
					IARG_UINT32, TraceEntryFlags::BranchTypeJump,
					IARG_RETURN_REGS, _nextBufferEntryReg,
					IARG_END);

				continue;
			}
			if(INS_IsRet(ins) && INS_IsControlFlow(ins))
			{
				// ret instructions cannot be instrumented with IPOINT_AFTER, since they do have no fallthrough
				INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(TraceWriter::InsertRetBranchEntry),
                    IARG_REG_VALUE, _traceWriterReg,
					IARG_REG_VALUE, _nextBufferEntryReg,
					IARG_INST_PTR,
					IARG_BRANCH_TARGET_ADDR,
					IARG_RETURN_REGS, _nextBufferEntryReg,
					IARG_END);

				// Store stack pointer value
				if(_enableStackAllocationTracking)
				{
					INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(TraceWriter::InsertStackPointerModificationEntry),
                        IARG_REG_VALUE, _traceWriterReg,
						IARG_REG_VALUE, _nextBufferEntryReg,
						IARG_INST_PTR,
						IARG_REG_VALUE, REG_RSP,
						IARG_UINT32, TraceEntryFlags::StackIsReturn,
						IARG_RETURN_REGS, _nextBufferEntryReg,
						IARG_END);
				}

#ifndef USE_LEGACY_ALLOC_RETURN_TRACKING
                // Trace allocation function returns
                INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(TrackAllocationReturn),
                    IARG_REG_VALUE, _traceWriterReg,
                    IARG_REG_VALUE, _nextBufferEntryReg,
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_RETURN_REGS, _nextBufferEntryReg,
                    IARG_END);
#endif
				continue;
			}

			// Ignore everything else in uninteresting images
			if(!interesting)
				continue;

			// Stack allocation tracking
			// ret is already tracked above; push/pop are ignored
			if(_enableStackAllocationTracking && INS_FullRegWContain(ins, REG_RSP))
			{
				INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(TraceWriter::InsertStackPointerModificationEntry),
                    IARG_REG_VALUE, _traceWriterReg,
					IARG_REG_VALUE, _nextBufferEntryReg,
					IARG_INST_PTR,
					IARG_REG_VALUE, REG_RSP,
					IARG_UINT32, TraceEntryFlags::StackIsOther,
					IARG_RETURN_REGS, _nextBufferEntryReg,
					IARG_END);
			}

			// Trace instructions with memory read
			if(INS_IsMemoryRead(ins) && INS_IsStandardMemop(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertMemoryReadEntry),
                    IARG_REG_VALUE, _traceWriterReg,
					IARG_REG_VALUE, _nextBufferEntryReg,
					IARG_INST_PTR,
					IARG_MEMORYREAD_EA,
					IARG_MEMORYREAD_SIZE,
					IARG_RETURN_REGS, _nextBufferEntryReg,
					IARG_END);
			}

			// Trace instructions with a second memory read operand
			if(INS_HasMemoryRead2(ins) && INS_IsStandardMemop(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertMemoryReadEntry),
                    IARG_REG_VALUE, _traceWriterReg,
					IARG_REG_VALUE, _nextBufferEntryReg,
					IARG_INST_PTR,
					IARG_MEMORYREAD2_EA,
					IARG_MEMORYREAD_SIZE, // IARG_MEMORYREAD2_SIZE does not exist, but we can assume that both operands have the same size
					IARG_RETURN_REGS, _nextBufferEntryReg,
					IARG_END);
			}

			// Trace instructions with memory write
			if(INS_IsMemoryWrite(ins) && INS_IsStandardMemop(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertMemoryWriteEntry),
                    IARG_REG_VALUE, _traceWriterReg,
					IARG_REG_VALUE, _nextBufferEntryReg,
					IARG_INST_PTR,
					IARG_MEMORYWRITE_EA,
					IARG_MEMORYWRITE_SIZE,
					IARG_RETURN_REGS, _nextBufferEntryReg,
					IARG_END);
			}
		}
	}
}

// [Callback] Creates a new trace logger for the given new thread.
VOID ThreadStart(THREADID tid, CONTEXT* ctxt, [[maybe_unused]] INT32 flags, [[maybe_unused]] VOID* v)
{
	// Only instrument main thread
	if(tid == 0)
	{
		// Create new trace logger for this thread
		auto* traceWriter = new TraceWriter(trim(KnobOutputFilePrefix.Value()));

		// Store logger
        PIN_SetContextReg(ctxt, _traceWriterReg, reinterpret_cast<ADDRINT>(traceWriter));

		// Initialize entry buffer pointers
		PIN_SetContextReg(ctxt, _nextBufferEntryReg, reinterpret_cast<ADDRINT>(traceWriter->Begin()));
		PIN_SetContextReg(ctxt, _entryBufferEndReg, reinterpret_cast<ADDRINT>(traceWriter->End()));
	}
	else
	{
		// Set entry buffer pointers as null pointers
		std::cerr << "Ignoring thread #" << tid << std::endl;
        PIN_SetContextReg(ctxt, _traceWriterReg, 0);
		PIN_SetContextReg(ctxt, _nextBufferEntryReg, 0);
		PIN_SetContextReg(ctxt, _entryBufferEndReg, 0);
	}
}

// [Callback] Cleans up after thread exit.
VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, [[maybe_unused]] INT32 code, [[maybe_unused]] VOID* v)
{
	// Only the main thread is instrumented
	if(tid != 0)
		return;

	// Finalize trace logger of this thread
	auto* traceWriter = reinterpret_cast<TraceWriter*>(PIN_GetContextReg(ctxt, _traceWriterReg));
	traceWriter->WriteBufferToFile(reinterpret_cast<TraceEntry*>(PIN_GetContextReg(ctxt, _nextBufferEntryReg)));
	delete traceWriter;
}

#ifdef USE_LEGACY_ALLOC_RETURN_TRACKING
#define InstrumentMemoryHeapAllocReturnAddress(...) do { \
    RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(TraceWriter::InsertHeapAllocAddressReturnEntry), \
        IARG_REG_VALUE, _traceWriterReg, \
		IARG_REG_VALUE, _nextBufferEntryReg, \
		__VA_ARGS__, \
		IARG_RETURN_REGS, _nextBufferEntryReg, \
		IARG_END); \
} while (0)
#else
#define InstrumentMemoryHeapAllocReturnAddress(...) do { \
    RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(StartAllocationTracking), \
        IARG_REG_VALUE, _nextBufferEntryReg, \
        IARG_END); \
} while (0)
#endif

#define InstrumentMalloc(fn, size_loc, ...) do { \
    RTN rtn = RTN_FindByName(img, fn); \
	if(RTN_Valid(rtn)) \
	{ \
		RTN_Open(rtn); \
		RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertHeapAllocSizeParameterEntry), \
            IARG_REG_VALUE, _traceWriterReg, \
			IARG_REG_VALUE, _nextBufferEntryReg, \
			IARG_FUNCARG_ENTRYPOINT_VALUE, size_loc, \
			IARG_RETURN_REGS, _nextBufferEntryReg, \
			IARG_END); \
		InstrumentMemoryHeapAllocReturnAddress(__VA_ARGS__); \
		RTN_Close(rtn); \
		std::cerr << "    " << fn << "() instrumented." << std::endl; \
	} else { \
		std::cerr << "    " << fn << "() not found." << std::endl; \
	} \
} while (0)

#define InstrumentCalloc(fn, num_loc, size_loc, ...) do { \
    RTN rtn = RTN_FindByName(img, fn); \
	if(RTN_Valid(rtn)) \
	{ \
		RTN_Open(rtn); \
		RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertCallocSizeParameterEntry), \
            IARG_REG_VALUE, _traceWriterReg, \
			IARG_REG_VALUE, _nextBufferEntryReg, \
			IARG_FUNCARG_ENTRYPOINT_VALUE, num_loc, \
			IARG_FUNCARG_ENTRYPOINT_VALUE, size_loc, \
			IARG_RETURN_REGS, _nextBufferEntryReg, \
			IARG_END); \
		InstrumentMemoryHeapAllocReturnAddress(__VA_ARGS__); \
		RTN_Close(rtn); \
		std::cerr << "    " << fn << "() instrumented." << std::endl; \
	} else { \
		std::cerr << "    " << fn << "() not found." << std::endl; \
	} \
} while (0)

#define InstrumentFree(fn, ptr_loc) do { \
    RTN rtn = RTN_FindByName(img, fn); \
	if(RTN_Valid(rtn)) \
	{ \
		RTN_Open(rtn); \
		RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertHeapFreeAddressParameterEntry), \
            IARG_REG_VALUE, _traceWriterReg, \
			IARG_REG_VALUE, _nextBufferEntryReg, \
			IARG_FUNCARG_ENTRYPOINT_VALUE, ptr_loc, \
			IARG_RETURN_REGS, _nextBufferEntryReg, \
			IARG_END); \
		RTN_Close(rtn); \
		std::cerr << "    " << fn << "() instrumented." << std::endl; \
	} else { \
		std::cerr << "    " << fn << "() not found." << std::endl; \
	} \
} while (0)

// [Callback] Instruments the memory allocation/deallocation functions.
VOID InstrumentImage(IMG img, [[maybe_unused]] VOID* v)
{
	// Retrieve image name
	std::string imageName = IMG_Name(img);

	// Check whether image is interesting (its name appears in the image name list passed over the command line)
	std::string imageNameLower = imageName;
	tolower(imageNameLower);
	INT8 interesting = (find_if(_interestingImages.begin(), _interestingImages.end(), [&](std::string& interestingImageName) { return imageNameLower.find(interestingImageName) != std::string::npos; }) != _interestingImages.end()) ? 1 : 0;

	// Retrieve image memory offsets
	UINT64 imageStart = IMG_LowAddress(img);
	UINT64 imageEnd = IMG_HighAddress(img);
	UINT32 numRegions = IMG_NumRegions(img);
	for(UINT32 r = 0; r < numRegions; ++r)
	{
		UINT64 low = IMG_RegionLowAddress(img, r);
		if(low < imageStart)
			imageStart = low;
		
		UINT64 high = IMG_RegionHighAddress(img, r);
		if(high > imageEnd)
			imageEnd = high;
	}

	// Record image data
	TraceWriter::WriteImageLoadData(static_cast<int>(interesting), imageStart, imageEnd, imageName);

	// Remember image for filtered trace instrumentation
	_images.push_back(new ImageData(interesting, imageName, imageStart, imageEnd));
	std::cerr << "Image '" << imageName << "' loaded at " << std::hex << imageStart << " ... " << std::hex << imageEnd << (interesting != 0 ? " [interesting]" : "") << std::endl;

	// libc?
	if (!_libcLoadDetected && imageName.find("libc.so") != std::string::npos)
	{
		_libcLoadDetected = true;
		std::cerr << "    libc detected" << std::endl;
	}

	// Find the Pin notification functions to insert testcase markers
	RTN notifyStartRtn = RTN_FindByName(img, "PinNotifyTestcaseStart");
	if(RTN_Valid(notifyStartRtn))
	{
		// Switch to next testcase
		RTN_Open(notifyStartRtn);
		RTN_InsertCall(notifyStartRtn, IPOINT_BEFORE, AFUNPTR(TestcaseStart),
			IARG_REG_VALUE, _traceWriterReg,
			IARG_REG_VALUE, _nextBufferEntryReg,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_RETURN_REGS, _nextBufferEntryReg,
			IARG_END);
		RTN_Close(notifyStartRtn);

		std::cerr << "    PinNotifyTestcaseStart() instrumented." << std::endl;
	}
	RTN notifyEndRtn = RTN_FindByName(img, "PinNotifyTestcaseEnd");
	if(RTN_Valid(notifyEndRtn))
	{
		// Close testcase
		RTN_Open(notifyEndRtn);
		RTN_InsertCall(notifyEndRtn, IPOINT_BEFORE, AFUNPTR(TestcaseEnd),
            IARG_REG_VALUE, _traceWriterReg,
			IARG_REG_VALUE, _nextBufferEntryReg,
			IARG_RETURN_REGS, _nextBufferEntryReg,
			IARG_END);
		RTN_Close(notifyEndRtn);

		std::cerr << "    PinNotifyTestcaseEnd() instrumented." << std::endl;
	}

	// Find the Pin stack pointer notification function
	RTN notifyStackPointerRtn = RTN_FindByName(img, "PinNotifyStackPointer");
	if(RTN_Valid(notifyStackPointerRtn))
	{
		// Save stack pointer value
		RTN_Open(notifyStackPointerRtn);
		RTN_InsertCall(notifyStackPointerRtn, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertStackPointerInfoEntry),
            IARG_REG_VALUE, _traceWriterReg,
			IARG_REG_VALUE, _nextBufferEntryReg,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_RETURN_REGS, _nextBufferEntryReg,
			IARG_END);
		RTN_Close(notifyStackPointerRtn);

		std::cerr << "    PinNotifyStackPointer() instrumented." << std::endl;
	}

	RTN notifyFilterRtn = RTN_FindByName(img, "PinNotifyFilter");
	if (RTN_Valid(notifyFilterRtn))
	{
		RTN_Open(notifyFilterRtn);
		RTN_InsertCall(notifyFilterRtn, IPOINT_BEFORE, AFUNPTR(SetFilter),
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);
		RTN_Close(notifyFilterRtn);

		std::cerr << "    PinNotifyFilter() instrumented." << std::endl;
	}

	RTN notifyFilterAddRtn = RTN_FindByName(img, "PinNotifyFilterAdd");
	if (RTN_Valid(notifyFilterAddRtn))
	{
		RTN_Open(notifyFilterAddRtn);
		RTN_InsertCall(notifyFilterAddRtn, IPOINT_BEFORE, AFUNPTR(AddFilter),
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
		RTN_Close(notifyFilterAddRtn);

		std::cerr << "    PinNotifyFilterAdd() instrumented." << std::endl;
	}

	RTN notifyFilterRemoveRtn = RTN_FindByName(img, "PinNotifyFilterRemove");
	if (RTN_Valid(notifyFilterRemoveRtn))
	{
		RTN_Open(notifyFilterRemoveRtn);
		RTN_InsertCall(notifyFilterRemoveRtn, IPOINT_BEFORE, AFUNPTR(RemoveFilter),
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);
		RTN_Close(notifyFilterRemoveRtn);

		std::cerr << "    PinNotifyFilterRemove() instrumented." << std::endl;
	}

	RTN notifyFilterPrintRtn = RTN_FindByName(img, "PinNotifyFilterPrint");
	if (RTN_Valid(notifyFilterPrintRtn))
	{
		RTN_Open(notifyFilterPrintRtn);
		RTN_InsertCall(notifyFilterPrintRtn, IPOINT_BEFORE, AFUNPTR(PrintFilter),
			IARG_END);
		RTN_Close(notifyFilterPrintRtn);

		std::cerr << "    PinNotifyFilterPrint() instrumented." << std::endl;
	}

	RTN notifyAliasRtn = RTN_FindByName(img, "PinNotifyAlias");
	if (RTN_Valid(notifyAliasRtn))
	{
		RTN_Open(notifyAliasRtn);
		RTN_InsertCall(notifyAliasRtn, IPOINT_BEFORE, AFUNPTR(TraceWriter::AddAlias),
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);
		RTN_Close(notifyAliasRtn);

		std::cerr << "    PinNotifyAlias() instrumented." << std::endl;
	}

	// Find the Pin allocation notification function
	RTN notifyAllocationRtn = RTN_FindByName(img, "PinNotifyAllocation");
	if(RTN_Valid(notifyAllocationRtn))
	{
		// Send allocation info
		RTN_Open(notifyAllocationRtn);
		RTN_InsertCall(notifyAllocationRtn, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertHeapAllocSizeParameterEntry),
            IARG_REG_VALUE, _traceWriterReg,
            IARG_REG_VALUE, _nextBufferEntryReg,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_RETURN_REGS, _nextBufferEntryReg,
            IARG_END);
		RTN_InsertCall(notifyAllocationRtn, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertHeapAllocAddressReturnEntry),
            IARG_REG_VALUE, _traceWriterReg,
            IARG_REG_VALUE, _nextBufferEntryReg,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_RETURN_REGS, _nextBufferEntryReg,
            IARG_END);
		RTN_Close(notifyAllocationRtn);

		std::cerr << "    PinNotifyAllocation() instrumented." << std::endl;
	}

	// Find runtime source file info debug function
	RTN SourceInfoRtn = RTN_FindByName(img, "PinNotifySourceInfo");
	if (RTN_Valid(SourceInfoRtn))
	{
		// Send source info
		RTN_Open(SourceInfoRtn);
		RTN_InsertCall(SourceInfoRtn, IPOINT_BEFORE, AFUNPTR(TraceWriter::InsertSourceInfoEntry),
			IARG_REG_VALUE, _traceWriterReg,
            IARG_REG_VALUE, _nextBufferEntryReg,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_RETURN_REGS, _nextBufferEntryReg,
			IARG_END);
		RTN_Close(SourceInfoRtn);

		std::cerr << "    PinNotifySourceInfo() instrumented." << std::endl;
	}

	if (KnobCustomMemoryFunctions.NumberOfValues() == 0)
	{
		// Find allocation and free functions to log allocation sizes and addresses
 #if defined(_WIN32)
        InstrumentMalloc("RtlAllocateHeap", 2, IARG_REG_VALUE, REG_RAX);
        InstrumentFree("RtlFreeHeap", 2);
#else
		// Only instrument allocation methods from libc
		if(imageName.find("libc.so") != std::string::npos)
		{
		    InstrumentMalloc("malloc", 0, IARG_FUNCRET_EXITPOINT_VALUE);
		    InstrumentCalloc("calloc", 0, 1, IARG_FUNCRET_EXITPOINT_VALUE);
		    InstrumentMalloc("realloc", 1, IARG_FUNCRET_EXITPOINT_VALUE);
		    InstrumentFree("free", 0);
		}
#endif
	} else {
	    std::cerr << "    disabling libc memory function instrumentation" << std::endl;

		for (UINT32 i = 0; i < KnobCustomMemoryFunctions.NumberOfValues(); ++i)
		{
			std::string cfg = KnobCustomMemoryFunctions.Value(i);

			std::string s;
			std::vector<std::string> parts;
			std::istringstream iss(cfg);
			while (std::getline(iss, s, ':'))
			{
                s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
                    return !std::isspace(ch);
                }));
                s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
                    return !std::isspace(ch);
                }).base(), s.end());
				parts.push_back(s);
			}

			if (parts.size() < 3)
			{
				std::cerr << "    invalid custom memory function format, requires at least 3 parts: " << cfg << std::endl;
				continue;
			}

			std::string type = parts[0];
			std::string fn = parts[1];
			int a0 = std::stoi(parts[2]);

			if ((type == "calloc" || type == "realloc") && parts.size() < 4) {
			    std::cerr << "    invalid custom memory function format, calloc and realloc require 2 arguments: " << cfg << std::endl;
				continue;
			}

			int a1 = parts.size() > 3 ? std::stoi(parts[3]) : 0;

			if (type == "malloc") {
			    InstrumentMalloc(fn.c_str(), a0, IARG_FUNCRET_EXITPOINT_VALUE);
			} else if (type == "calloc") {
			    InstrumentCalloc(fn.c_str(), a0, a1, IARG_FUNCRET_EXITPOINT_VALUE);
			} else if (type == "realloc") {
			    InstrumentMalloc(fn.c_str(), a0, a1, IARG_FUNCRET_EXITPOINT_VALUE);
			} else if (type == "free") {
			    InstrumentFree(fn.c_str(), a0);
			} else {
			    std::cerr << "    invalid custom memory function type: " << type << std::endl;
			}
		}
	}
}

// Handles the beginning of a testcase.
TraceEntry* TestcaseStart(TraceWriter *traceWriter, TraceEntry* nextEntry, ADDRINT newTestcaseId)
{
	// Get trace logger object and set the new testcase ID
	traceWriter->TestcaseStart(static_cast<int>(newTestcaseId), nextEntry);
	return traceWriter->Begin();
}

// Handles the ending of a testcase.
TraceEntry* TestcaseEnd(TraceWriter *traceWriter, TraceEntry* nextEntry)
{
	// Get trace logger object and set the new testcase ID
	traceWriter->TestcaseEnd(nextEntry);
	return traceWriter->Begin();
}

// Handles an internal exception of this trace tool.
EXCEPT_HANDLING_RESULT HandlePinToolException([[maybe_unused]] THREADID tid, EXCEPTION_INFO* exceptionInfo, [[maybe_unused]] PHYSICAL_CONTEXT* physicalContext, [[maybe_unused]] VOID* v)
{
	// Output exception data
	std::cerr << "Internal exception: " << PIN_ExceptionToString(exceptionInfo) << std::endl;
	return EHR_UNHANDLED;
}

// Converts the given trace entry pointer into its address integer (which is then checked for NULL by Pin).
ADDRINT CheckNextTraceEntryPointerValid(TraceEntry* nextEntry)
{
	return reinterpret_cast<ADDRINT>(nextEntry);
}

VOID StartAllocationTracking(TraceEntry *nextEntry)
{
    // Check whether given entry pointer is valid (we might be in a non-instrumented thread)
    if(nextEntry == nullptr)
        return;

    _allocationCallStackDepth = 0;
}

VOID TrackAllocationCall()
{
    if(_allocationCallStackDepth >= 0)
        ++_allocationCallStackDepth;
}

// Checks whether the current allocation tracking call stack is exited. If it is, the returned allocation address is stored in the trace.
TraceEntry* TrackAllocationReturn(TraceWriter *traceWriter, TraceEntry *nextEntry, ADDRINT returnValue)
{
    // Tracking active?
    if(_allocationCallStackDepth < 0)
        return nextEntry;

    // Return
    --_allocationCallStackDepth;

    // Have we reached the end of the call stack?
    if(_allocationCallStackDepth < 0)
        return TraceWriter::InsertHeapAllocAddressReturnEntry(traceWriter, nextEntry, returnValue);

    return nextEntry;
}

// Overwrites the given destination register of the RDRAND instruction with a constant value.
void ChangeRandomNumber(ADDRINT* outputReg)
{
	*outputReg = static_cast<ADDRINT>(_fixedRandomNumber);
}

void PrintFilter() {
    for (const auto& entry : filter)
    {
        bool whitelisted = FilterTypeMatch(FilterTypeWhiteList, entry.type);

        bool cf = FilterTypeMatch(FilterTypeControlFlow, entry.type);
        bool da = FilterTypeMatch(FilterTypeDataAccess, entry.type);

        bool jump = FilterTypeMatch(FilterTypeJump, entry.type);
        bool call = FilterTypeMatch(FilterTypeCall, entry.type);
        bool ret = FilterTypeMatch(FilterTypeReturn, entry.type);
        bool linearize = FilterTypeMatch(FilterTypeLinearize, entry.type);

        bool read = FilterTypeMatch(FilterTypeRead, entry.type);
        bool write = FilterTypeMatch(FilterTypeWrite, entry.type);

        std::cerr << "Filter entry: ";
        if (entry.originStart && entry.originEnd)
            std::cerr << (void *) entry.originStart << " - " << (void *) entry.originEnd << " -> ";
        else
            std::cerr << "? -> ";

        if (entry.targetStart && entry.targetEnd)
            std::cerr << (void *) entry.targetStart << " - " << (void *) entry.targetEnd << " ";
        else
            std::cerr << "? ";

        std::cerr << (whitelisted ? "(+)" : "(-)") << " ";
        if (cf) {
            std::cerr << "CF(";
            if (jump)
                std::cerr << "jump";
            if (call) {
                if (jump)
                    std::cerr << ", ";
                std::cerr << "call";
                if (linearize)
                    std::cerr << " -> linearize";
            }
            if (ret) {
                if (jump || call)
                        std::cerr << ", ";
                    std::cerr << "return";
            }
            std::cerr << ")";
        }

        if (da) {
            if (cf)
                std::cerr << " ";
            std::cerr << "DA(";
            if (read)
                std::cerr << "read";
            if (write) {
                if (read)
                        std::cerr << ", ";
                    std::cerr << "write";
            }
            std::cerr << ")";
        }

        std::cerr << std::endl;
    }
}

void SetFilter(FilterEntry *addr, size_t size)
{
    for(size_t i = 0; i < size; ++i) {
        if ((addr[i].originStart == 0 || addr[i].originEnd == 0) && (addr[i].targetStart == 0 || addr[i].targetEnd == 0))
            continue;
        filter.push_back(addr[i]);
    }
}

void AddFilter(FilterEntry *entry)
{
    if (entry->originStart == 0 && entry->originEnd == 0 && entry->targetStart == 0 && entry->targetEnd == 0)
        return;
    filter.push_back(*entry);
}

void RemoveFilter(FilterType type, ADDRINT origin, ADDRINT target)
{
    filter.erase(std::remove_if(filter.begin(), filter.end(), [&](const FilterEntry& entry) {
        return FilterTypeMatch(type, entry.type) &&
            (origin == 0 || (entry.originStart == origin && entry.originEnd == origin) || (entry.originStart <= origin && origin < entry.originEnd)) &&
            (target == 0 || (entry.targetStart == target && entry.targetEnd == target) || (entry.targetStart <= target && target < entry.targetEnd));
    }), filter.end());
}

#pragma clang diagnostic pop
