import sys, os

class memory:
  def __init__ (self, addr, size, value):
    self.size = size
    self.addr = addr
    self.value = value
  def __str__(self):
    return "a:%016x s:%08x v:%016x" % (self.addr, self.size, self.value)
        
class instruction:
  def __init__(self):
    self.ip = 0
    self.tid = 0
    self.opcodes = []
    self.disass = ""
    self.partial_context = {}   #partial context of modified regs only
    self.full_context = {} # full context in case of this instruction is head of basic block
    self.reads = []     #memory 
    self.writes = []    #memroy 
  def __str__(self):
    return "%08x %016x %-30s %-30s" % (self.tid, self.ip, " ".join(["%02x" % c for c in self.opcodes]), self.disass )
    
def parse_trace_log(trace_file):
  instructions = [] 
  
  split_val = lambda expr: expr.split("=")[1]
  top_ins = lambda: instructions[-1]
  def top_match_ins(ip):
    if not instructions:
      return False
    return instructions[-1].ip == ip
      
  with open(trace_file, "r") as ifd:
    for line in [_.strip() for _ in ifd.readlines()]:
      toks = line.split()
      if not toks:
        continue
      # instruction and context
      if toks[0] == "[I]":
        tid = int(toks[1], 16)
        ip = int(toks[2], 16)
        idx = 3
        # parse opcodes
        ops = []
        while 1:
          try:
            if len(toks[idx]) > 2:
              break
            ops.append(int(toks[idx], 16))
            idx += 1
          except ValueError as e:
            break
        # parse assembly code
        asms = []
        while idx < len(toks):
          if "=" in toks[idx]:
            break
          asms.append(toks[idx])
          idx += 1
        # parse context
        ctx = {}
        while idx < len(toks):
          reg, value = toks[idx].split("=")
          ctx[reg] = int(value, 16)
          idx += 1
          
        if top_match_ins(ip):
          top_ins().partial_context.update(ctx)
          top_ins().disass = " ".join(asms)
          top_ins().opcodes.extend(ops)
        else:
          ins = instruction()
          ins.ip = ip; ins.tid = tid;
          ins.partial_context.update(ctx)
          ins.disass = " ".join(asms)
          ins.opcodes.extend(ops)
          instructions.append(ins)
          
      # memory R/W
      elif toks[0] in ["[R]", "[W]"]:
        #'00000000', '000000003f5e145a', 'addr=000000003f5e2008', 'size=00000008', 'value=0000000076df3ee0'
        tid = int(toks[1], 16)
        ip = int(toks[2], 16)
        mem = memory(int(split_val(toks[3]), 16), int(split_val(toks[4]), 16), int(split_val(toks[5]), 16))
        if toks[0] == "[R]":
          if top_match_ins(ip):
            top_ins().reads.append(mem)
          else:
            ins = instruction(); 
            ins.ip = ip; ins.tid = tid;
            ins.reads.append(mem)
            instructions.append(ins)
        else:
          if top_match_ins(ip):
            top_ins().writes.append(mem)
          else:
            ins = instruction(); 
            ins.ip = ip; ins.tid = tid;
            ins.writes.append(mem)
            instructions.append(ins)
      
      # basic block start, record full context
      elif toks[0] == "[B]":
        _, __, full_context = line.split("//")
        ctx = {}
        for reg_val in full_context.split():
          reg, val = reg_val.split("=")
          ctx[reg] = int(val, 16)
        ins = instruction()
        ins.tid = int(toks[1], 16)
        ins.ip = int(toks[2], 16)
        ins.full_context.update(ctx)
        instructions.append(ins)
        
  return instructions

def print_instructions_accessing_memory(logfile, address, size):
  mem_access_in_range = lambda addr: addr >= address and addr <= (address+size)
  
  instrns = parse_trace_log(logfile)
  for ins in instrns:
    if ins.reads:
      for m in ins.reads:
        if mem_access_in_range(m.addr) or mem_access_in_range(m.value):
          print "{0} [R] {1}".format(ins.__str__(), "%08x = %08x" % (m.addr, m.value))
    if ins.writes:
      for m in ins.writes:
        if mem_access_in_range(m.addr) or mem_access_in_range(m.value):
          print "{0} [W] {1}".format(ins.__str__(), "%08x = %08x" % (m.addr, m.value))
          
if __name__ == "__main__":
  if len(sys.argv) == 4:
    print_instructions_accessing_memory(sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3]))
