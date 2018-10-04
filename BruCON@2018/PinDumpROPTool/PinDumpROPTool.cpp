#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <iomanip>
#include <stack>
#include <set>
#include <string>
#include <algorithm>
#include <iterator>
#include <stdarg.h>


using namespace std;

std::ofstream traceFile;


PIN_LOCK lock;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "rop_trace.txt", "specify trace file name");

ADDRINT low, high; 

const int N_INSTRUCTIONS_TO_DUMP = 8;
unsigned int nInstructionsDumped = 0;

std::set<ADDRINT> ReturnSites; 

void OnImageLoad(IMG Img, void *v)
{
	traceFile << "ImageLoad: 0x" << hex << IMG_LowAddress(Img) << " - 0x" << IMG_HighAddress(Img) << " " << IMG_Name(Img) << endl;
}

void OnImageUnload(IMG Img, void *v)
{
	traceFile << "ImageUnLoad: " << IMG_Name(Img) << endl;
}


void OnInstruction(THREADID tid, ADDRINT addr, UINT32 size, string* ins)
{
	if (nInstructionsDumped != 0) {
		traceFile << "         " << hex << addr << " " << *ins << endl;
		nInstructionsDumped--;
	}
}

void OnCallIns(THREADID tid, ADDRINT ip, ADDRINT target, ADDRINT size)
{
	ReturnSites.insert(ip + size);
}

void OnCallInsIndirect(THREADID tid, ADDRINT ip, ADDRINT target, BOOL taken, ADDRINT size)
{
	if (!taken)
		return;
	OnCallIns(tid, ip, target, size);
}

void OnRetIns(THREADID tid, ADDRINT ip, ADDRINT target)
{
	if (ReturnSites.find(target) == ReturnSites.end()) {
		traceFile << endl << "Possible Jump To ROP! Thread " << hex << tid
			<< " From " << hex << ip
			<< " (" << RTN_FindNameByAddress(ip) << ")"
			<< " To " << hex << target
			<< " (" << RTN_FindNameByAddress(target) << ")" << endl;
		nInstructionsDumped = N_INSTRUCTIONS_TO_DUMP;
	}
}

void OnTrace(TRACE trace, void *v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		INS ins = BBL_InsTail(bbl);
		if (INS_IsCall(ins))
		{
			if (INS_IsDirectBranchOrCall(ins))
			{
				const ADDRINT target = INS_DirectBranchOrCallTargetAddress(ins);

				INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
					AFUNPTR(OnCallIns), IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins),	IARG_ADDRINT, target, 
					IARG_ADDRINT, INS_Size(ins), IARG_END);
			}
			else
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(OnCallInsIndirect), 
					IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins), IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, 
					IARG_ADDRINT, INS_Size(ins), IARG_END);
			}
		}
		else if (INS_IsRet(ins)) 
		{
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
				AFUNPTR(OnRetIns), IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins),	IARG_RETURN_IP, IARG_END);
		}
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			string* disass = new string(INS_Disassemble(ins));
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(OnInstruction),
				IARG_THREAD_ID, IARG_ADDRINT, BBL_Address(bbl), IARG_UINT32, BBL_Size(bbl), IARG_PTR, disass, IARG_END);
		}
	}
}

VOID Fini(INT32 code, VOID *v)
{
	traceFile.close();
}

int  main(int argc, char *argv[])
{
	PIN_InitSymbols();

	if (PIN_Init(argc, argv))
		return 0;

	if (!KnobOutputFile.Value().empty())
	{
		traceFile.open(KnobOutputFile.Value().c_str());
	}

	//Register instrumentation Callbacks!
	IMG_AddInstrumentFunction(OnImageLoad, 0);
	IMG_AddUnloadFunction(OnImageUnload, 0);

	TRACE_AddInstrumentFunction(OnTrace, 0);
	//INS_AddInstrumentFunction(OnInstruction, 0);
	
	PIN_AddFiniFunction(Fini, 0);

	// Never returns
	PIN_StartProgram();

	return 0;
}

