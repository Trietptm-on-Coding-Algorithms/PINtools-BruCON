#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <iomanip>
#include <map>
#include <string>
#include <algorithm>
#include <iterator>
#include <stdarg.h>

using namespace std;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

FILE *logfp;
#define LOG_PRINTF(fmt, ...) do { if(logfp) { fprintf(logfp, fmt, __VA_ARGS__); } } while (0)

PIN_LOCK lock;

ADDRINT _moduleBegin, _moduleEnd;

typedef std::vector<std::pair<ADDRINT, ADDRINT>> TraceFilterRange;
TraceFilterRange _traceFilters;

//CONTEXT management
#define MAX_REG_PARTS 6  /*rax eax ax ah al none*/

struct RegisterReference
{
	std::string       name[MAX_REG_PARTS];
	std::string		  alias;
	LEVEL_BASE::REG   ref;
};

static struct RegisterReference AllContextRegs[] =
{
#if defined(__x86_64__) || defined(_M_X64)	
  { { "rax", "eax", "ax", "ah", "al", "" }, "rax", LEVEL_BASE::REG_RAX },
  { { "rbx", "ebx", "bx", "bh", "bl", "" }, "rbx", LEVEL_BASE::REG_RBX },
  { { "rcx", "ecx", "cx", "ch", "cl", "" }, "rcx", LEVEL_BASE::REG_RCX },
  { { "rdx", "edx", "dx", "dh", "dl", "" }, "rdx", LEVEL_BASE::REG_RDX },
  { { "rdi", "edi", "di", "" }, "rdi", LEVEL_BASE::REG_RDI },
  { { "rsi", "esi", "si", "" }, "rsi", LEVEL_BASE::REG_RSI },
  { { "rsp", "esp", "sp", "" }, "rsp", LEVEL_BASE::REG_RSP },
  { { "rbp", "ebp", "bp", "" }, "rbp", LEVEL_BASE::REG_RBP },
  { { "rip", "eip", "ip", "" }, "rip", LEVEL_BASE::REG_RIP },
  { { "r8", "" }, "r8", LEVEL_BASE::REG_R8 },
  { { "r9", "" }, "r9", LEVEL_BASE::REG_R9 },
  { { "r10", "" }, "r10", LEVEL_BASE::REG_R10 },
  { { "r11", "" }, "r11", LEVEL_BASE::REG_R11 },
  { { "r12", "" }, "r12", LEVEL_BASE::REG_R12 },
  { { "r13", "" }, "r13", LEVEL_BASE::REG_R13 },
  { { "r14", "" }, "r14", LEVEL_BASE::REG_R14 },
  { { "r15", "" }, "r15", LEVEL_BASE::REG_R15 },
  { { "eflags", "" }, "eflags", LEVEL_BASE::REG_RFLAGS },
#endif
#if defined(__i386) || defined(_M_IX86)
  { { "eax", "ax", "ah", "al", "" }, "eax", LEVEL_BASE::REG_EAX },
  { { "ebx", "bx", "bh", "bl", "" }, "ebx", LEVEL_BASE::REG_EBX },
  { { "ecx", "cx", "ch", "cl", "" }, "ecx", LEVEL_BASE::REG_ECX },
  { { "edx", "dx", "dh", "dl", "" }, "edx", LEVEL_BASE::REG_EDX },
  { { "edi", "di", "" }, "edi", LEVEL_BASE::REG_EDI },
  { { "esi", "si", "" }, "esi", LEVEL_BASE::REG_ESI },
  { { "eip", "ip", "" }, "eip", LEVEL_BASE::REG_EIP },
  { { "esp", "sp", "" }, "esp", LEVEL_BASE::REG_ESP },
  { { "ebp", "bp", "" }, "ebp", LEVEL_BASE::REG_EBP },
  { { "eflags", "" }, "eflags", LEVEL_BASE::REG_EFLAGS },
#endif
  { { "fs", "" }, "fs", REG_SEG_FS },
  { { "gs", "" }, "gs", REG_SEG_GS },
  { { "" }, "", REG_INVALID() }
};


/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "trace-full-info.txt", "specify trace file name");
KNOB<BOOL> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "enable if you want to trace instructions");
KNOB<BOOL> KnobTraceBasicBlocks(KNOB_MODE_WRITEONCE, "pintool", "b", "0", "enable if you want to log basic block trace");
KNOB<BOOL> KnobTraceFunctionCalls(KNOB_MODE_WRITEONCE, "pintool", "c", "0", "enable if you want to trace function calls");
KNOB<BOOL> KnobTraceThreads(KNOB_MODE_WRITEONCE, "pintool", "t", "0", "enable if you want to trace threads activities");
KNOB<BOOL> KnobTraceModules(KNOB_MODE_WRITEONCE, "pintool", "m", "0", "enable if you want to trace module load/unload activity");
KNOB<string> KnobFilterModule(KNOB_MODE_WRITEONCE, "pintool", "fm", "main", "filter module to trace, default is main executable");
KNOB<string> KnobFilterOffsets(KNOB_MODE_WRITEONCE, "pintool", "fo", "", "comma separated list of filter offsets relative to filter module in form of 0x100-0x200,...");


/* ===================================================================== */
/* Helper Functions                                                      */
/* ===================================================================== */

BOOL IsAddressInTraceRange(ADDRINT address)
{
	if (_traceFilters.empty())
		return (address >= _moduleBegin && address <= _moduleEnd);
	else {
		TraceFilterRange::const_iterator rangeItr = _traceFilters.begin();
		for (; rangeItr != _traceFilters.end(); rangeItr++)
		{
			if (address >= rangeItr->first && address <= rangeItr->second)
				return TRUE;
		}
	}
	return FALSE;
}

std::vector<string> SplitString(std::string str, char seperator)
{
	vector<string> strings;
	istringstream iss(str);
	string s;
	while (getline(iss, s, seperator)) 
		strings.push_back(s);
	return strings;
}

INT32 Usage()
{
	cerr << "*** Program Tracer! ***" << endl;
	cerr << "Trace progra executaion with (module load/unload, basic blocks/instruction level/ memroy read/write support/ thread / calls logs" << endl;
	cerr << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

/* ===================================================================== */
/* Helper Functions for OnInstruction                                   */
/* ===================================================================== */

VOID PrintCurrentContext(CONTEXT *ctx, string *disass, BOOL all=FALSE)
{
	if (all)
	{
		for (int i = 0; !(AllContextRegs[i].name[0].empty()); i++)
			LOG_PRINTF("%s=%016x ", AllContextRegs[i].alias.c_str(), 
				PIN_GetContextReg(ctx, AllContextRegs[i].ref));
	}
	else
	{
		if (disass->find("call") != string::npos)
			return;

		for (int i = 0; !(AllContextRegs[i].name[0].empty()); i++)
		{
			for (int j = 0; j < MAX_REG_PARTS; j++)
			{
				if (AllContextRegs[i].name[j].empty()) break; 
				if (disass->find(AllContextRegs[i].name[j]) != string::npos)
				{
					LOG_PRINTF("%s=%016x ", AllContextRegs[i].alias.c_str(), 
						PIN_GetContextReg(ctx, AllContextRegs[i].ref));
					break;
				}
			}
		}
	}
	
	
#if defined(__x86_64__) || defined(_M_X64)
	LOG_PRINTF("eflags=%016x ", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RFLAGS));
#elif defined(__i386) || defined(_M_IX86)
	LOG_PRINTF("eflags=%016x ", PIN_GetContextReg(ctx, LEVEL_BASE::REG_EFLAGS));
#endif
}

VOID LogInstruction(THREADID tid, ADDRINT ip, string *disass, CONTEXT *ctx, INT32 size)
{
	UINT8 v[32];
	CHAR  opcode[128] = { 0 };

	if ((size_t)size > sizeof(v))
		return;

	PIN_GetLock(&lock, ip);

	if (1) 
	{
#if defined(__x86_64__) || defined(_M_X64)
		LOG_PRINTF("[I]	%08x %016x ", tid, ip);
#elif defined(__i386) || defined(_M_IX86)
		LOG_PRINTF("[I]	%08x %016x ", tid, ip);
#endif

		PIN_SafeCopy(v, (void *)ip, size);
		for (INT32 i = 0; i < size; i++)
			sprintf((char*)opcode + i * 3, "%02x ", v[i]);

		LOG_PRINTF("%-40s ", opcode);

		string ins = *disass;
		LOG_PRINTF("%-50s ", ins.c_str());

		PrintCurrentContext(ctx, disass);

		//TODO: BELOW delete causes crash, wtf
		//delete disass;
		LOG_PRINTF("\n");
	}

	PIN_ReleaseLock(&lock);
}

static VOID LogMemoryAccess(THREADID tid, ADDRINT ip, CHAR r, ADDRINT addr, UINT8* memdump, INT32 size, BOOL isPrefetch)
{
	LOG_PRINTF("[%c] %08x %016x	%-91s addr=%016x size=%08x ", r, tid, ip, "", addr, size);

	if (!isPrefetch)
	{
		switch (size)
		{
		case 0: break; 
		case 1: LOG_PRINTF("value=%016x", *(INT32*)memdump); break;
		case 2: LOG_PRINTF("value=%016x", *(INT16*)memdump); break;
		case 4: LOG_PRINTF("value=%016x", *(INT32*)memdump); break;
		case 8: LOG_PRINTF("value=%016x", *(INT64*)memdump); break;
		default:
			LOG_PRINTF("value=");
			for (INT32 i = 0; i < size; i++)
				LOG_PRINTF("\\x%02x", memdump[i]);
			break;
		}
	}
	LOG_PRINTF("%s", "\n");
}

static VOID OnMemoryAccess(THREADID tid, ADDRINT ip, CHAR r, ADDRINT addr, INT32 size, BOOL isPrefetch)
{
	UINT8 memdump[256] = { 0 };
	PIN_GetLock(&lock, ip);
	if ((size_t)size > sizeof(memdump))
	{
		PIN_ReleaseLock(&lock);
		return;
	}
	PIN_SafeCopy(memdump, (void *)addr, size);
	
	if (1) {
		LogMemoryAccess(tid, ip, r, addr, memdump, size, isPrefetch);
	}

	PIN_ReleaseLock(&lock);
}

static ADDRINT WriteAddr;
static INT32 WriteSize;

static VOID RecordWriteAddrSize(ADDRINT addr, INT32 size)
{
	WriteAddr = addr;
	WriteSize = size;
}


static VOID OnMemoryAccessWrite(THREADID tid, ADDRINT ip)
{
	OnMemoryAccess(tid, ip, 'W', WriteAddr, WriteSize, false);
}

/* ================================================================================= */
/* This is called for each instruction                                               */
/* ================================================================================= */
VOID OnInstruction(INS ins, VOID *v)
{
	if (IsAddressInTraceRange(INS_Address(ins))) 
	{
		if (INS_IsMemoryRead(ins))
			INS_InsertPredicatedCall( ins, IPOINT_BEFORE, (AFUNPTR)OnMemoryAccess, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, 'R', 
						IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, INS_IsPrefetch(ins), IARG_END);

		if (INS_HasMemoryRead2(ins))
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)OnMemoryAccess, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, 'R',
				IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, INS_IsPrefetch(ins), IARG_END);

		if (INS_IsMemoryWrite(ins))
		{
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteAddrSize, IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE, IARG_END);

			if (INS_HasFallThrough(ins))
				INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)OnMemoryAccessWrite, IARG_THREAD_ID, IARG_INST_PTR, IARG_END);
			
			if (INS_IsBranchOrCall(ins))
				INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)OnMemoryAccessWrite, IARG_THREAD_ID, IARG_INST_PTR, IARG_END);
		}

		string* disass = new string(INS_Disassemble(ins));
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogInstruction,IARG_THREAD_ID, IARG_INST_PTR, IARG_PTR, disass, IARG_CONTEXT, 
			IARG_UINT32, INS_Size(ins), IARG_END);
	}
}

VOID SetupFilters()
{
	string filterOffsets = KnobFilterOffsets.Value();
	if (!filterOffsets.empty())
	{
		std::vector<string> offsets = SplitString(filterOffsets, ',');
		for (std::vector<string>::const_iterator tok = offsets.begin(); tok != offsets.end(); tok++)
		{
			std::vector<string> range = SplitString(*tok, '-');
			if (range.size() == 2) {
				_traceFilters.push_back(
					std::make_pair<ADDRINT, ADDRINT>(strtoul(range[0].c_str(), 0, 16) + _moduleBegin,
					strtoul(range[1].c_str(), 0, 16) + _moduleBegin));
			}
		}
	}
}

void OnImageLoad(IMG Img, void *v)
{
	PIN_GetLock(&lock, 0);

	if (KnobTraceModules.Value())
		LOG_PRINTF("[M] ModuleLoad %s %012x-%012x\n", IMG_Name(Img).c_str(), IMG_LowAddress(Img), IMG_HighAddress(Img));

	if (KnobFilterModule.Value() == "main")
	{
		if (IMG_IsMainExecutable(Img)) {
			_moduleBegin = IMG_LowAddress(Img), _moduleEnd = IMG_HighAddress(Img);
			//setup offsets filter relative to module begin
			SetupFilters();
		}
	}
	else
	{
		if (IMG_Name(Img).find(KnobFilterModule.Value().c_str()) != string::npos) {
			cerr << "instrumenting " << IMG_Name(Img) << endl;
			_moduleBegin = IMG_LowAddress(Img), _moduleEnd = IMG_HighAddress(Img);
			//setup offsets filter relative to module begin
			SetupFilters();
		}
	}

	PIN_ReleaseLock(&lock);
}

void OnImageUnload(IMG Img, void *v)
{
	//TODO: when tracing shared libraries, if traced library gets unloaded, remove filters
	if (KnobTraceModules.Value())
		LOG_PRINTF("[M] ModuleUnLoad %s %012x-%012x\n", IMG_Name(Img).c_str(), IMG_LowAddress(Img), IMG_HighAddress(Img));
}

/* ===================================================================== */
/* Helper Functions for OnTrace                                         */
/* ===================================================================== */

void OnBasicBlock(THREADID tid, ADDRINT addr, UINT32 size, CONTEXT* context)
{
	PIN_GetLock(&lock, addr);
	string name = RTN_FindNameByAddress(addr);
	if (name.empty())
		LOG_PRINTF("\n[B] %08x %016x loc_%016x: // size=%d // ", tid, addr, addr, size);
	else
		LOG_PRINTF("\n[B] %08x %016x %s: // size=%d // ", tid, addr, name.c_str(), size);
	PrintCurrentContext(context, 0, TRUE);
	LOG_PRINTF("\n");

	PIN_ReleaseLock(&lock);
}

void LogCallAndArgs(THREADID tid, ADDRINT ip, ADDRINT target, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
	string nameFunc = RTN_FindNameByAddress(target);

	PIN_GetLock(&lock, ip);
	LOG_PRINTF("[C]	%08x %016x call %016x (%s) (%016x, %016x, %016x)\n", tid, ip, target, nameFunc.c_str(), arg0, arg1, arg2);
	PIN_ReleaseLock(&lock);
}

void LogIndirectCallAndArgs(THREADID tid, ADDRINT ip, ADDRINT target, BOOL taken, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
	if (!taken)
		return;
	LogCallAndArgs(tid, ip, target, arg0, arg1, arg2);
}


VOID OnCallInstruction(TRACE trace, INS ins)
{
	if (INS_IsCall(ins))
	{
		if (INS_IsDirectBranchOrCall(ins))
		{
			const ADDRINT target = INS_DirectBranchOrCallTargetAddress(ins);

			INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
				AFUNPTR(LogCallAndArgs),				// Function to jump to
				IARG_THREAD_ID,
				IARG_ADDRINT, INS_Address(ins),			// callers address
				IARG_ADDRINT,							// "target"'s type
				target, IARG_FUNCARG_ENTRYPOINT_VALUE,                             // Who is called?
				// Arg_0 value
				0, IARG_FUNCARG_ENTRYPOINT_VALUE,      // Arg_1 value
				1, IARG_FUNCARG_ENTRYPOINT_VALUE,      // Arg_2 value
				2, IARG_END);
		}
		else
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(LogIndirectCallAndArgs), IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins), IARG_BRANCH_TARGET_ADDR,
				IARG_BRANCH_TAKEN, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE,
				1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
		}
	}
	else
	{
		/* Other forms of execution transfer */
		RTN rtn = TRACE_Rtn(trace);
		// Trace jmp into DLLs (.idata section that is, imports)
		if (RTN_Valid(rtn) && SEC_Name(RTN_Sec(rtn)) == ".idata")
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(LogIndirectCallAndArgs), IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins), IARG_BRANCH_TARGET_ADDR,
				IARG_BRANCH_TAKEN, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE,
				1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
		}
	}
}

void OnTrace(TRACE trace, void *v)
{
	if (IsAddressInTraceRange(TRACE_Address(trace)))
	{
		/* Iterate through basic blocks */
		for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			INS head = BBL_InsHead(bbl);
			
			/* instrument BBL_InsHead to write "loc_XXXXX", like in IDA Pro */
			if (KnobTraceBasicBlocks.Value())
				INS_InsertCall(head, IPOINT_BEFORE, (AFUNPTR)OnBasicBlock, IARG_THREAD_ID, IARG_ADDRINT, BBL_Address(bbl), 
									IARG_UINT32, BBL_Size(bbl), IARG_CONTEXT, IARG_END);

			if (KnobTraceInstructions.Value())
			{
				//instrument every instruction in this trace
				for (INS ins = head; INS_Valid(ins); ins = INS_Next(ins))
					OnInstruction(ins, 0);
			}
			
			/* Instrument function calls? */
			if (KnobTraceFunctionCalls.Value())
				OnCallInstruction(trace, BBL_InsTail(bbl));
		}
	}
}

/* ================================================================================= */
/* Log some information related to thread execution                                  */
/* ================================================================================= */
void OnThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	PIN_GetLock(&lock, threadIndex + 1);
	LOG_PRINTF("[T]	THREAD STARTED 0x%08x flags: 0x%08x\n", PIN_ThreadUid(), flags);
	PIN_ReleaseLock(&lock);
}


void OnThreadFinish(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	PIN_GetLock(&lock, threadIndex + 1);
	LOG_PRINTF("[T]	THREAD ENDED 0x%08x code: 0x%08x\n", PIN_ThreadUid(), code);
	PIN_ReleaseLock(&lock);
}

VOID Fini(INT32 code, VOID *v)
{
	fclose(logfp);
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int  main(int argc, char *argv[])
{
	if (PIN_Init(argc, argv))
		return Usage();

	PIN_InitSymbols();

	if (!KnobOutputFile.Value().empty())
	{
		logfp = fopen(KnobOutputFile.Value().c_str(), "wb");
		if (!logfp)
			logfp = stderr;
	}
	else logfp = stderr;

	//Register instrumentation Callbacks!
	IMG_AddInstrumentFunction(OnImageLoad, 0);
	IMG_AddUnloadFunction(OnImageUnload, 0);

	if (KnobTraceThreads.Value())
	{
		PIN_AddThreadStartFunction(OnThreadStart, 0);
		PIN_AddThreadFiniFunction(OnThreadFinish, 0);
	}

	TRACE_AddInstrumentFunction(OnTrace, 0);
	//INS_AddInstrumentFunction(OnInstruction, 0);
	
	PIN_AddFiniFunction(Fini, 0);

	// Never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
