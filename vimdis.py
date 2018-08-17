#!/usr/bin/env python2.7
#
# vimdis.py by m4rkw - edit binary files with vim :P
#
# uses otool to disassemble Mach-O binaries
# edit opcode bytes and save the file to patch
#
# patched lines will be indicated so you know that the instructions after the
# opcode are no longer correct
#
# you can make this "vi" or "vim" in your path and it will
# still find and execute the real vim correctly.

import sys
import os
import re
import uuid
import hashlib
import shutil

DEFAULT_OPCODE_WIDTH  = 8
ARCH_PREFERENCE_ORDER = ['x86_64', 'i386']

class Dis:
  def __init__(self):
    self.vim = self.get_vim_path()
    self.datadir = "%s/.vimdis" % (os.environ['HOME'])

    if not os.path.exists(self.datadir):
      os.mkdir(self.datadir, 0755)


  def usage(self):
    print "disas: %s [-32] [-64] <file> [file] [..]" % (sys.argv[0])
    sys.exit(0)


  def get_vim_path(self):
    i = os.path.abspath(__file__)

    for path in os.environ['PATH'].split(':'):
      vim_path = path + '/vim'

      if vim_path != i and os.path.exists(vim_path):
        return vim_path

    raise Exception("vim not found in PATH")


  def validate_arch(self, path, arch):
    arches = []

    for line in os.popen("/usr/bin/file '%s'" % (path)).read().rstrip().split("\n"):
      match = re.match("^.*?Mach-O.*?executable (.*?)$", line)

      if match:
        arches.append(match.group(1))

    if len(arches) == 0:
      return False

    if arch in arches:
      return arch

    for pref_arch in ARCH_PREFERENCE_ORDER:
      if pref_arch in arches:
        print "warning: %s arch not found, loading %s instead..." % (arch, pref_arch)
        return pref_arch

    return arches[0]


  def sha256(self, path):
    m = hashlib.sha256()

    try:
      f = open(path,'r')
    except:
      print "failed to open %s" % (path)
      return False

    while 1:
      block = f.read(10240)

      if not block:
        break

      m.update(block)

    f.close()

    return m.hexdigest()


  def disas(self, path, arch):
    arch = self.validate_arch(path, arch)

    if not arch:
      os.system("%s '%s'" % (self.vim, path))
      return

    sha256 = self.sha256(path)

    tmpfile = "%s/%s.%s" % (self.datadir, os.path.abspath(path).replace('/','_'), arch)

    lines = None

    if os.path.exists(tmpfile):
      lines = open(tmpfile).read().split("\n")

      match = re.match("^sha256: ([\da-f]{64})$", lines[0])

      if not match or match.group(1) != sha256:
        lines = None

    if lines == None:
      print "disassembling %s arch=%s ..." % (path, arch)

      lines = ["sha256: %s" % (sha256)]
      lines += os.popen("otool -arch %s -jtvV '%s'" % (arch, path)).read().split("\n")

      opcode_width = DEFAULT_OPCODE_WIDTH

      for line in lines:
        match = re.match("^[\da-f]+", line)

        if match:
          seg = line.split('\t')
          opcode = seg[1].replace(' ','')

          if len(opcode) > opcode_width:
            opcode_width = len(opcode)

      with open(tmpfile,'w') as f:
        for line in lines:
          line = line.rstrip()

          match = re.match("^[\da-f]+", line)

          if match:
            seg = line.split('\t')

            offset = seg[0]
            opcode = seg[1].replace(' ','')
            instr = " ".join(seg[2:])

            f.write("%s    %s    %s\n" % (offset, opcode.ljust(opcode_width), instr))
          else:
            if len(line) >0 and line[-1] == ':':
              f.write("\n")
            f.write("%s\n" % (line))
            if len(line) >0 and line[-1] == ':':
              f.write("\n")

    shutil.copyfile(tmpfile, "%s.bak" % (tmpfile))

    sha256_before = self.sha256(tmpfile)

    os.system("%s %s" % (self.vim, tmpfile))

    if self.sha256(tmpfile) != sha256_before:
      new = open(tmpfile, 'r').read().split("\n")
      old = open("%s.bak" % (tmpfile), 'r').read().split("\n")

      if len(new) != len(old):
        print "ERROR: file must have the same number of lines!"
        os.rename("%s.bak" % (tmpfile), tmpfile)
        sys.exit(1)

      data = None

      modified_lines = []

      for i in range(0, len(new)):
        new_line = new[i]
        old_line = old[i]

        old_match = re.match("^([\da-f]+)[\s\t]+([\da-f]+)[\s\t]+", old_line)
        new_match = re.match("^([\da-f]+)[\s\t]+([\da-f]+)[\s\t]+", new_line)

        if old_match and new_match and old_match.group(2) != new_match.group(2):
          modified_lines.append(i)

          print "patching %s: %s => %s" % (new_match.group(1), old_match.group(2), new_match.group(2))

          if len(old_match.group(2)) != len(new_match.group(2)):
            print "ERROR: number of opcode bytes cannot change!"
            os.rename("%s.bak" % (tmpfile), tmpfile)
            sys.exit(1)

          if data == None:
            data = list(open(path, 'r').read())

          data = self.patch(path, new_match.group(1), new_match.group(2), data)

      if data != None:
        with open(path, 'w') as f:
          f.write("".join(data))

        lines = open(tmpfile,'r').read().split("\n")

        lines[0] = 'sha256: %s' % (self.sha256(path))

        for i in modified_lines:
          if '** PATCHED **' not in lines[i]:
            lines[i] += '  ** PATCHED **'

        with open(tmpfile,'w') as f:
          f.write("\n".join(lines))

    os.remove("%s.bak" % (tmpfile))


  def patch(self, path, offset, opcode, data):
    x = list(offset)
    x[7] = '0'
    offset = "".join(x)

    offset_dec = int(offset, 16)

    for i in range(0, len(opcode), 2):
      op = int(opcode[i] + opcode[i+1], 16)
      data[offset_dec + i] = chr(int(opcode[i] + opcode[i+1], 16))

    return data


d = Dis()

if len(sys.argv) <2:
  d.usage()

arch = ARCH_PREFERENCE_ORDER[0]
paths = []

for i in range(1, len(sys.argv)):
  if sys.argv[i] == '-32':
    arch = 'i386'
  elif sys.argv[i] == '-64':
    arch = 'x86_64'
  else:
    paths.append(sys.argv[i])

if len(paths) == 0:
  d.usage()

for path in paths:
  if not os.path.exists(path):
    print "%s does not exist!" % (path)
  else:
    d.disas(path, arch)
