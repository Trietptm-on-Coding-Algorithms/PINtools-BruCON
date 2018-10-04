import sys
import os
import struct
from ctypes import *
import idaapi, idautils
import sark 
import pdb
import time
from idautils import *
import collections

last, inc, dec  = lambda ll, i=1: ll and ll[-i], lambda x:x+1, lambda x:x-1

class ida_function:
  def __init__(self, va, fn=None):
    self.va = va  #address 
    self.fn = fn and fn or sark.Function(va)
    self.ret_blocks = []
    self.is_only_trampoline = False 
    self._analyse()
    
  def _analyse(self):
    n_ret = 0
    n_blocks = 0
    for block in sark.codeblocks(self.fn.startEA, self.fn.endEA):
      code_line = list(block.lines)
      if not code_line:
        continue
      last_line = last(code_line)
      if "align" in last_line.disasm[:6]:
        last_line = last(code_line, 2)
      if "ret" in last_line.disasm[:4]:
        n_ret += 1
        self.ret_blocks.append(block.startEA)
      n_blocks += 1
      
    if n_ret == 0:
      self.is_only_trampoline = True
      if 1:
        return
      if n_blocks == 1:
        block = sark.CodeBlock(self.va)
        lines = list(block.lines)
        if len(lines) > 1 and "jmp" in last(lines).disasm[:4]:
          self.is_only_trampoline = True
    
  def contains_call_to_fn(self, va):
    pass
    
  def contains_call_from_fn(self, va):  
    pass
    
  def is_ret_block(self, va):
    if va in self.ret_blocks:
      return True
  
  def is_fn_only_trampoline(self):
    return self.is_only_trampoline
    
def get_dll_export_entries():
  exports = {} 
  for e in idautils.Entries():
    _, __, addr, name  = e
    exports[addr] = name
  return exports

def demangle_name(name):
  dname = Demangle(name, INF_SHORT_DN)
  return dname and dname or name
  
def if_functions_contains_multiple_returns(entries):
  for addr, name in entries.items():
    fn = ida_function(addr)
    if not fn.ret_blocks:
      print "%08x %s %s" % (addr, name, fn.is_fn_only_trampoline())
    
#
# routine 
# 
sark_fn_cache = {} 
def does_fn_have_call_to(src_va, dst_va):
  fn = None 
  if src_va in sark_fn_cache:
    fn = sark_fn_cache[src_va]
  else:
    fn = sark.Function(src_va)
    sark_fn_cache[src_va] = fn
  for xref in fn.xrefs_from:
    if xref.to == dst_va:
      return True 
  return False
  
class cfg_fn_node:
  def __init__(self, va, name="_external_", parent=None):
    self.va = va
    self.name = name 
    self.childs = [] 
    self.parent = parent
    if self.parent:
      self.parent.add_child(self)
      
  def have_call_to(self, dst_va):
    if self.name == "_external_":
      return True 
    elif self.name == "_guard_check_icall":
      return True
    return does_fn_have_call_to(self.va, dst_va)
  def add_child(self, node):
    self.childs.append(node) 
    
def print_graph(root, outstream=sys.stdout):
  stack = [(root, 0)]
  while stack:
    node, indent = stack.pop()
    outstream.write("%s%08x:%s\n" % (" " * indent, node.va, node.name))
    for child in node.childs[::-1]:
      stack.append((child, indent+1))
          
def build_exports_cfg(bb_list):
  base = idaapi.get_imagebase()
  
  _first_ = bb_list[0].start+base
  fn = sark.Function(_first_)
  opti_bb_list  = [(_first_, demangle_name(fn.name))]
  
  for bb in bb_list:
    va = bb.start+base 
    try:
      fn = sark.Function(va)
    except:
      continue
    fn_name = demangle_name(fn.name)
    if fn_name != opti_bb_list[-1][1]:
      opti_bb_list.append((va, demangle_name(fn.name)))
  
  #with open(r"C:\Users\JohnDoe\Desktop\ChakraCore\hehe.txt", "a") as ofd:
  #  for e in opti_bb_list:
  #    va, name = e 
  #    ofd.write("%08x %s\n" % (va, name))
  #if (1):
  #  return 
    
  exported_apis = get_dll_export_entries().values() 
  # start cfg building  
  root = cfg_fn_node(0) 
  cur_node = root 
  
  i  = 0
  for entry in opti_bb_list:
    va, name = entry
    if cur_node.have_call_to(va):
      cur_node = cfg_fn_node(va, name, cur_node)
    else:
      # two_options? it is in parent or indirect call, 
      check_node = cur_node
      while check_node != root:
        check_node = check_node.parent 
        if check_node.have_call_to(va):
          cur_node = cfg_fn_node(va, name, check_node); break
        elif check_node.name == name:
          cur_node = check_node; break 
          
      if check_node == root:
        if name in exported_apis:
          cur_node = cfg_fn_node(va, name, root)  
        else:
          print "indirect call unlinked %d %08x %s %s" % (i, va, name, cur_node.name)
          #print_graph(root)
          return 
    i +=1

  return root
  
#
# Pin bb read 
#
class basicblock(Structure):
  _pack_   = 1
  _fields_ = [
    ('tid',  c_uint16),
    ('size',   c_uint16),
    ('start', c_uint32)
  ]

def bb_read_pin_logs(bbtrace_log_path):
  with open(bbtrace_log_path, "rb") as ifd:
    while 1:
      bb = basicblock()
      if ifd.readinto(bb):
        yield bb
      else: break

def group_logs_by_thread_id(bb_generator):
  m = {} 
  for bb in bb_generator:
    if bb.tid in m:
      m[bb.tid].append(bb)
    else: m[bb.tid] = [bb]
  return m
  
def main(pin_bb_log_file, out_dir) :
  for tid, bb_gen in group_logs_by_thread_id(bb_read_pin_logs(pin_bb_log_file)).items():
    with open(os.path.join(out_dir, "{:04d}.log".format(tid)), "w") as ofd:
      print_graph(build_exports_cfg(bb_gen), ofd)


s_t = time.time()
# main call    
main(r"G:\pin-2.14\source\tools\PinBBTrace\bbtrace.out", r"G:\pin-2.14\source\tools\PinBBTrace\result")
s_e = time.time()
print (s_e - s_t)