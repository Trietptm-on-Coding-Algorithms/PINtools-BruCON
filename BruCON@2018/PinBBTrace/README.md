Intel Pin tool to instrument basic blocks and dump each executable basic block in the form of 

struct entry { 
    uint16 thread_id; 
    uint16 size; 
    uint32 start_offset_from_module;
  } 

to the output file. 

Processing output file to derive coverage information and generating CFG is included in "scripts" folder. 
