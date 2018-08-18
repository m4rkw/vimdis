#!/usr/bin/env python2.7
#
# vimdis.py by m4rkw - edit binary files with vim :P
#
# uses otool to disassemble Mach-O binaries on macOS and
# objdump to disassemble ELF binaries on Linux
#
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
PLATFORMS = {
  "darwin": "^([\da-f]+)[\t]([\da-f\s]+)[\t](.*?)$",
  "linux": "^[\s\t]*([\da-f]+):[\t]([\da-f\s]+)[\t](.*?)$"
}

class Dis:
  def __init__(self):
    self.vim = self.get_vim_path()
    self.datadir = "%s/.vimdis" % (os.environ['HOME'])
    self.platform = str.lower(os.popen("uname").read().rstrip())

    if self.platform not in ['darwin', 'linux']:
      print "unsupported platform: %s" % (self.platform)
      sys.exit(1)

    if not os.path.exists(self.datadir):
      os.mkdir(self.datadir, 0755)


  def usage(self):
    print "disas: %s [-32] [-64] <file> [file] [..]" % (sys.argv[0])
    sys.exit(0)


  def escape(self, string):
    return "'" + string.replace("'", "'\\''") + "'"


  def get_vim_path(self):
    i = os.path.abspath(__file__)

    for path in os.environ['PATH'].split(':'):
      vim_path = path + '/vim'

      if vim_path != i and os.path.exists(vim_path):
        return vim_path

    raise Exception("vim not found in PATH")


  def validate_arch(self, path, arch):
    arches = []

    for line in os.popen("/usr/bin/file %s" % (self.escape(path))).read().rstrip().split("\n"):
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


  def platform_call(self, method_prefix, args):
    method = getattr(self, '%s_%s' % (method_prefix, self.platform))

    return method(*args)


  def disassemble_darwin(self, arch, path):
    return os.popen("otool -arch %s -jtvV %s" % (arch, self.escape(path))).read().split("\n")


  def disassemble_linux(self, arch, path):
    return os.popen("objdump -d %s" % (self.escape(path))).read().split("\n")


  def disas(self, path, arch):
    if self.platform == 'darwin':
      arch = self.validate_arch(path, arch)

      if not arch:
        return False

    sha256 = self.sha256(path)

    tmpfile = "%s/%s.%s" % (self.datadir, os.path.abspath(path).replace('/','_'), arch)

    lines = None

    if os.path.exists(tmpfile):
      lines = open(tmpfile).read().split("\n")

      match = re.match("^sha256: ([\da-f]{64})$", lines[0])

      if not match or match.group(1) != sha256:
        lines = None

    if lines != None:
      print "cached: %s arch=%s ..." % (path, arch)
    else:
      print "disassembling %s arch=%s ..." % (path, arch)

      lines = ["sha256: %s" % (sha256)]
      lines += self.platform_call('disassemble', [arch, path])

      opcode_width = self.get_opcode_width(lines)

      with open(tmpfile,'w') as f:
        for line in lines:
          line = line.rstrip()

          detail = self.parse_code_line(line)

          if detail:
            f.write("%s    %s    %s\n" % (detail["offset"], detail["opcode"].ljust(opcode_width), detail["instr"]))
          else:
            if len(line) >0 and line[-1] == ':':
              f.write("\n")
            f.write("%s\n" % (line))
            if len(line) >0 and line[-1] == ':':
              f.write("\n")

    shutil.copyfile(tmpfile, "%s.bak" % (tmpfile))

    return tmpfile


  def parse_code_line(self, line):
    match = re.match(PLATFORMS[self.platform], line)

    if match:
      return {
        "offset": match.group(1),
        "opcode": match.group(2).replace(' ',''),
        "instr": match.group(3)
      }

    return False


  def get_opcode_width(self, lines):
    opcode_width = DEFAULT_OPCODE_WIDTH

    for line in lines:
      detail = self.parse_code_line(line)

      if detail and len(detail["opcode"]) > opcode_width:
        opcode_width = len(detail["opcode"])

    return opcode_width


  def edit(self, paths, disas):
    cmd = self.vim

    for path in paths:
      if path in disas.keys():
        cmd += " %s" % (self.escape(disas[path]["path"]))
      else:
        cmd += " %s" % (self.escape(path))

    os.system(cmd)
    

  def patch(self, paths, disas):
    for path in paths:
      if path not in disas.keys():
        continue

      sha256_before = disas[path]["sha256"]
      tmpfile = disas[path]["path"]

      if sha256_before == self.sha256(tmpfile):
        print "%s: no change" % (path)
      else:
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

            offset = self.get_offset(new_match.group(1))

            print "%s: patching 0x%s: %s => %s" % (path, offset, old_match.group(2), new_match.group(2))

            if len(old_match.group(2)) != len(new_match.group(2)):
              print "ERROR: number of opcode bytes cannot change!"
              os.rename("%s.bak" % (tmpfile), tmpfile)
              sys.exit(1)

            if data == None:
              data = list(open(path, 'r').read())

            data = self.patch_bytes(path, offset, new_match.group(2), data)

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


  def get_offset(self, offset):
    if self.platform != 'darwin':
      return offset

    x = list(offset)
    x[7] = '0'

    while x[0] == '0':
      x = x[1:]

    offset = "".join(x)

    return offset


  def patch_bytes(self, path, offset, opcode, data):
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

disas = {}

for path in paths:
  if os.path.exists(path):
    tmpfile = d.disas(path, arch)

    if tmpfile:
      disas[path] = {
        "path": tmpfile,
        "sha256": d.sha256(tmpfile)
      }

d.edit(paths, disas)
d.patch(paths, disas)
