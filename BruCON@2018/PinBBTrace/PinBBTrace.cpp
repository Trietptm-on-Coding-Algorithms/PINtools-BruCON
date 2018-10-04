
#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <vector>

using namespace std;

FILE *out;

#pragma pack(1)
typedef struct bb_entry {
	unsigned short tid; 
	unsigned short size;
	unsigned int start;
}bb_entry_t;

#define MAX_CACHE_SIZE (1024 * 4)
bb_entry_t basic_block_storage[MAX_CACHE_SIZE];
UINT16 cache_index = 0;

ADDRINT module_low_limit = 0, module_high_limit = 0;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "bbtrace.out", "specify file name for BBTrack output");
KNOB<string>   KnobTraceModule(KNOB_MODE_WRITEONCE, "pintool", "m", "main", "module to trace, default is main executable");

INT32 Usage()
{
	cerr << "This tool dumps basic blocks executed" << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}


static VOID DumpCacheToFile()
{
	for (int i = 0; i < cache_index; i++)
		fwrite(&basic_block_storage[i], sizeof(bb_entry_t), 1, out);
	cache_index = 0;
}

VOID PIN_FAST_ANALYSIS_CALL BasicBlockCallbackProc(THREADID tid, UINT32 size, ADDRINT address_bb)
{
	/*basic_block_storage[cache_index].tid = tid; 
	basic_block_storage[cache_index].size = size;
	basic_block_storage[cache_index].start = address_bb - module_low_limit;
	cache_index++;
	if (cache_index == MAX_CACHE_SIZE)
		DumpCacheToFile();*/
	bb_entry_t entry = { tid, size, address_bb - module_low_limit };
	fwrite(&entry, sizeof(bb_entry_t), 1, out);
}


VOID Trace(TRACE trace, VOID *v)
{
	ADDRINT addr = TRACE_Address(trace);
	if (addr >= module_low_limit && addr <= module_high_limit)
	{
		for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BasicBlockCallbackProc,
				IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, BBL_Size(bbl), IARG_ADDRINT, BBL_Address(bbl), IARG_END);
		}
	}
}

VOID ImageLoadInstrumentation(IMG img, VOID * v)
{
	cerr << "Module Loaded: " << IMG_Name(img) << endl;

	if (KnobTraceModule.Value() == "main")
	{
		if (IMG_IsMainExecutable(img))
			module_low_limit = IMG_LowAddress(img), module_high_limit = IMG_HighAddress(img);
	}
	else
	{
		if (IMG_Name(img).find(KnobTraceModule.Value()) != string::npos)
			module_low_limit = IMG_LowAddress(img), module_high_limit = IMG_HighAddress(img);
	}
}


VOID Fini(INT32 code, VOID *v)
{
	//DumpCacheToFile();
	if (out)
		fclose(out);
}

int main(int argc, char *argv[])
{
	if (PIN_Init(argc, argv))
		return Usage();

	string fileName = KnobOutputFile.Value();

	if (!fileName.empty()) { 
		out = fopen(fileName.c_str(), "wb");
		if (!out) {
			cerr << "unable to open log file!" << endl;
			return 0;
		}
	}

	TRACE_AddInstrumentFunction(Trace, 0);
	IMG_AddInstrumentFunction(ImageLoadInstrumentation, 0);
	PIN_AddFiniFunction(Fini, 0);

	cerr << "===============================================" << endl;
	cerr << "This application is instrumented by PinBBTrace pintool!" << endl;
	if (!KnobOutputFile.Value().empty())
	{
		cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
	}
	cerr << "===============================================" << endl;

	PIN_StartProgram();

	return 0;
}
