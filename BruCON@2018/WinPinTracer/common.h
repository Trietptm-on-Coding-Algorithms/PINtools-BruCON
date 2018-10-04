#pragma once


#define INS		0
#define CALL	1

typedef struct tagInstructionField
{
	unsigned char opcodes[15];
}InstructionField;

typedef struct tagLogEntry
{
	unsigned char	type; 
	unsigned short	size;
	unsigned int	thread_id; 
	unsigned long	insptr; 
	union {

	}field_entry;
}LogEntry;



#define EVENT_MODULELOAD	1
#define EVENT_MODULEUNLOAD	2

typedef struct tagModuleLoadEvent
{
	unsigned short MLoadEventType;
	unsigned long moduleBegin;
	unsigned long moduleEnd;
	unsigned char moduleName[512];
};