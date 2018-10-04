import sys
import os
import struct
import sark 
import time
import idaapi, idautils
from idautils import *
from ctypes import *

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

class fn_node:
  def __init__(self, fn=None, parent=None):
    self.fn = fn
    self.childs = []
    self.parent = parent
    self.bbs = []
    if self.parent:
      self.parent.childs.append(self)
    self.note = ""
  def is_bb_part_of_fn(self, bb_va):
    if self.fn:
      if bb_va >= self.fn.startEA and bb_va <= self.fn.endEA:
        return True
      va_fn = sark.Function(bb_va)
      if va_fn.startEA == self.fn.startEA:
        return True
        
  def has_call_to(self, bb_va):
    if self.fn:
      for xref in self.fn.xrefs_from:
        if xref.to == bb_va: return True
  def to_string(self):
    return "%s %08x" % (self.fn and self.fn.name or "<unknown>", self.fn and self.fn.startEA or 0xdead)
  def add_bb(self, bb):
    self.bbs.append(bb)


def get_dll_export_entries():
  exports = {} 
  for e in idautils.Entries():
    _, __, addr, name  = e
    exports[addr] = name
  return exports
  
def get_control_flow_graph(imagebase, bb_collection_gen, verbose=False):
  exported_apis_addresses = get_dll_export_entries().keys()
  root = fn_node()
  cur_fn = root 
  last_bb, last_size = 0, 0
  for bb in bb_collection_gen:
    va = bb.start+imagebase
    fn = sark.Function(va)
    
    if fn.startEA == va:
      note = ""
      last_asm_code = last_bb > 0 and sark.Line(last_bb+last_size-1).disasm or "call _external_"
      if "ret" in last_asm_code:
        if cur_fn.is_bb_part_of_fn(va):
          cur_fn.add_bb(va)
          continue
        while cur_fn.parent and not cur_fn.has_call_to(va):
          cur_fn = cur_fn.parent
        if cur_fn == root:
          if not (va in exported_apis_addresses):
            note = "[_unlinked_] "
      cur_fn = fn_node(fn, cur_fn)
      cur_fn.note = note
    else:
      if cur_fn.is_bb_part_of_fn(va):
        cur_fn.add_bb(va)
      else:
        while cur_fn.parent and not cur_fn.is_bb_part_of_fn(va):
          cur_fn = cur_fn.parent 
        cur_fn.add_bb(va)
        
    last_bb, last_size = va, bb.size
  return root 
    
def group_logs_by_thread_id(bb_generator):
  m = {} 
  for bb in bb_generator:
    if bb.tid in m:
      m[bb.tid].append(bb)
    else: m[bb.tid] = [bb]
  return m

def demangle_name(name):
  dname = Demangle(name, INF_SHORT_DN)
  return dname and dname or name
  
def generate_cfg_logs(pin_bb_log_file, out_dir):
  for tid, bb_gen in group_logs_by_thread_id(bb_read_pin_logs(pin_bb_log_file)).items():
    with open(os.path.join(out_dir, "{:04d}.log".format(tid)), "w") as ofd:
      stack = [(get_control_flow_graph(idaapi.get_imagebase(), bb_gen), 0)]
      while stack:
        node, indent = stack.pop()
        if node.fn: ofd.write("%s%s%s\n" % (" " * indent, node.note, demangle_name(node.fn.name)))
        else: ofd.write("%s%s\n" % (" " * indent, "_external_"))
        for child in node.childs[::-1]:
          stack.append((child, indent+1))
     
s_t = time.time()
generate_cfg_logs(r"G:\pin-2.14\source\tools\PinBBTrace\bbtrace.out", r"G:\pin-2.14\source\tools\PinBBTrace\result")
s_e = time.time()
print (s_e - s_t)