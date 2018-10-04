import sys
import os
import struct
from ctypes import *
import pdb
import time
import collections

import r2pipe
r2 = r2pipe.open("/tmp/pin_bb/read.exe")
r2.cmd('aaa')
# print(r2.cmd("afl"))

last, inc, dec  = lambda ll, i=1: ll and ll[-i], lambda x:x+1, lambda x:x-1

def get_dll_export_entries():
  exports = {} 
  for e in idautils.Entries():
    _, __, addr, name  = e
    exports[addr] = name
  return exports

def demangle_name(name):
  dname = Demangle(name, INF_SHORT_DN)
  return dname and dname or name
  
#
# routine 
# 
sark_fn_cache = {} 
def does_fn_have_call_to(src_va, dst_va):
  print hex(src_va),"->", hex(dst_va)
  fn = None 
  dst_fn = r2.cmd("fd 0x%x" % dst_va).split(' + ')[0]
  if src_va in sark_fn_cache:
    fn = sark_fn_cache[src_va]
  else:
    fn = r2.cmd("fd 0x%x" % src_va).split(' + ')[0]
    sark_fn_cache[src_va] = fn
  print "This is from %s" % fn
  print "This is to %s" % dst_fn
  xrefs = r2.cmd("axt %s~CALL~[0]" % dst_fn).split("\n")
  print "Xrefs", xrefs
  for xref in xrefs:
    # f_name = r2.cmd("fd %s" % xref).split(' + ')[0]
    # print f_name
    if xref == fn:
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
  base = 0x400000
  
  #_first_ = bb_list[0].start+base
  #fn = sark.Function(_first_)
  #opti_bb_list  = [(_first_, demangle_name(fn.name))]
  opti_bb_list  = [(0, "_external_")]
  for bb in bb_list:
    va = bb.start+base 
    fn_name = r2.cmd("fd 0x%x" % va).split(' + ')[0]
    if fn_name != opti_bb_list[-1][1]:
      opti_bb_list.append((va, fn_name))
  
  exported_apis = {} 

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
          print "[*] indirect call unlinked %d %08x %s %s" % (i, va, name, cur_node.name)
        
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
  
def cfg(pin_bb_log_file, out_dir) :
  for tid, bb_gen in group_logs_by_thread_id(bb_read_pin_logs(pin_bb_log_file)).items():
    with open(os.path.join(out_dir, "{:04d}.log".format(tid)), "w") as ofd:
      print_graph(build_exports_cfg(bb_read_pin_logs(pin_bb_log_file)), ofd)

def coverage(pin_bb_log_file):
  base = 0x400000
  covered_functions = set() 
  for bb in bb_read_pin_logs(pin_bb_log_file):
    sark.CodeBlock(bb.start+base).color = 0xffff00
    sark_fn = sark.Function(bb.start + base)
    covered_functions.add(sark_fn.name)
  
  all_functions = set()
  for fn in sark.functions():
    all_functions.add(fn.name)
    
  print "function coverage summary! coverage {:.0f}%".format(float(len(covered_functions)) / float(len(all_functions)) * 100) 
  
s_t = time.time()
# main call
#coverage(r"G:\pin-2.14\source\tools\PinBBTrace\bbtrace.out")
cfg("./bbtrace.out", r"./result")
s_e = time.time()
print "script finished in {:.2f} seconds".format(s_e - s_t)