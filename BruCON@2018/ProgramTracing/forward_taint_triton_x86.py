import sys
import os
import struct

try:
  TRITON_DIST_PATH = r"F:\NinjaTools\Frameworks\TritonDist"
  sys.path.append(TRITON_DIST_PATH)
  from triton import *
except ImportError:
  print "triton dist path is not set"
  sys.exit(404)
  
from parse_log import *

def forward_taiting_x86(log_file, address, size):
  print "[*] reading logs..."
  insts = parse_trace_log(log_file)
  print "[*] done!"
  if not insts:
    print "[-] parsing error!"
    return
    
  triton_ctx = TritonContext()
  triton_ctx.setArchitecture(ARCH.X86)
  
  #for i in range(5, 4): triton_ctx.taintMemory(ADDR+i, 4)
  triton_ctx.taintMemory(MemoryAccess(0x15f9d8, 1))
  
  print "[*] processing instructions..."
  context = {} 
  for ins in insts:
    #print hex(ins.ip), ins.disass
    inst = Instruction()
    #print " ".join(["%02x" % x for x in ins.opcodes])
    opcode = "".join([r"%02x" % x for x in ins.opcodes])
    inst.setOpcode(opcode.decode("hex"))
    inst.setAddress(ins.ip)
    
    if ins.full_context:
      context.update(ins.full_context)
    else:
      context.update(ins.partial_context)
    
    # set context
    for reg, value in context.items():
      triton_ctx.setConcreteRegisterValue(getattr(triton_ctx.registers, reg), value)
    # set eip 
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.eip, ins.ip)
    
    if ins.reads:
      for m in ins.reads:
        triton_ctx.setConcreteMemoryValue(MemoryAccess(m.addr, m.size), m.value)
    
    if ins.writes:
      for m in ins.writes:
        triton_ctx.setConcreteMemoryValue(MemoryAccess(m.addr, m.size), m.value)
      
    triton_ctx.processing(inst)
    
    if inst.isTainted():
      print inst
  
  print "[*] done!"
  
if __name__ == "__main__":
  if len(sys.argv) == 4:
    forward_taiting_x86(sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3]))