Intel Pin tool to monitor program execution traces! 

Inspired and derived from -> https://github.com/SideChannelMarvels/Tracer/tree/master/TracerPIN

Modifications:
  - refactoring to remove database dump to keep code clean and minimal, only text entries
  - filtering approach
  - support for module based filtering, default is to main executable module 
  - support for range of offsets for filtering in case if you want to monitor for specific basic blocks or functions
  - added context dump on basic blocks and instructions 
  - script to parse logs in order to process it in python? may feed it to external cancolic execution framework like triton!
  
Example trace of a program and processing scripts are included in parent foder (ProgramTracing)
