import sys
import json
from capstone import *
from capstone.arm import *

def ToInteger(strval):
    if strval.upper().startswith("0X"):
        val = int(strval,base=0)
    elif strval.upper().endswith("K"):
        val = int(strval[:-1]) * 1024
    elif strval.upper().endswith("M"):
        val = int(strval[:-1]) * 1024 * 1024
    else:
        val = int(strval)
    return val

# Open the JSON definitions file
with open(sys.argv[1]) as jsonData:
    metadata = json.load(jsonData)

# Import the memory map definitions
if 'memory' in metadata.keys():
    print "Memory Regions"
    for m in metadata["memory"]:
        if 'length' not in m.keys():
            m["length"] = ToInteger("4")
        else:
            m["length"] = ToInteger(m["length"])
        m["address"] = ToInteger(m["address"])
        print "0x{0:08x}-0x{1:08x}:{2:3}:{3}".format(m["address"],m["address"]+m["length"]-1,m["access"],m["label"])

# Import the known object definitions
if 'objects' in metadata.keys():
    print "Objects"
    for o in metadata["objects"]:
        if 'length' not in o.keys():
            o["length"] = ToInteger("4")
        else:
            o["length"] = ToInteger(o["length"])
        o["address"] = ToInteger(o["address"])
        print "0x{0:08x}:0x{1:08x}:{2}".format(o["address"],o["length"],o["label"])

def GetKnownObjectName(addr):
    if 'objects' in metadata.keys():
        for o in metadata["objects"]:
            if o["address"] == addr:
                return o["label"]
    return ""

################################################################################
# dump the contents of a byte array at the specified offset and return the 
# number of bytes dumped
def dumpline(buff, offset):
    hexes = ""
    asciis = ""
    for b in buff:
        hexes = hexes + "{0:02x} ".format(b)
        if b >= 0x20 and b <= 0x7e:
        #    asciis = asciis + b.decode
            asciis = asciis + chr(b)
        else:
            asciis = asciis + "."

    print '{0:08x}: {1} {2}'.format(offset,hexes,asciis)
    return 16

################################################################################
# create a byte array of specified length
def zeros(length):
    z = bytearray(length)
    return z

def ProcessDefault(inst):
    print "0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str)

def ProcessVerbose(inst):
    print "0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str)
    if len(inst.regs_read) > 0:
        print("\tImplcit registers read:")
        for r in inst.regs_read:
           print("\t\t%s " %inst.reg_name(r))
        
    if len(inst.operands) > 0:
        print("\tNumber of operands: %u" %len(inst.operands))
        c = 0
        for o in inst.operands:
            if o.type == ARM_OP_IMM:
                print "\t\toperands[%u].type: IMM = 0x%x" %(c, o.value.imm)
            if o.type == ARM_OP_REG:
                print "\t\toperands[%u].type: REG = %s" %(c, inst.reg_name(o.value.reg))
            c += 1

#        if len(i.groups) > 0:
#            print("\tThis instruction belongs to groups:")
#            for g in i.groups:
#                print("\t\t%u" %g)
#            print

def ProcessBranch(inst):
    oper = inst.operands[0]
    ea = inst.address
    if oper.type == ARM_OP_IMM:
        ea = inst.address + 8 + oper.value.imm
        print "0x%x:\t%s\t%s\t(goto 0x%x)" %(inst.address, inst.mnemonic, inst.op_str, ea)
    else:
        ProcessDefault(inst)

def ProcessBranchLong(inst):
    oper = inst.operands[0]
    ea = inst.address
    if oper.type == ARM_OP_IMM:
        ea = inst.address + 8 + oper.value.imm
        name = GetKnownObjectName(ea)
        if name == "":
            print "0x%x:\t%s\t%s\t(call 0x%x)" %(inst.address, inst.mnemonic, inst.op_str, ea)
        else:
            print "0x%x:\t%s\t%s\t(call %s)" %(inst.address, inst.mnemonic, inst.op_str, name)
    else:
        ProcessDefault(inst)

def ProcessBitClear(inst):
    op1 = inst.reg_name(inst.operands[0].value.reg)
    op2 = inst.reg_name(inst.operands[1].value.reg)
    op3 = inst.operands[2]
    print "0x%x:\t%s\t%s\t(%s := %s & ~0x%08x)" %(inst.address, inst.mnemonic, inst.op_str, op1, op2, op3.value.imm)

def ProcessOrr(inst):
    op1 = inst.reg_name(inst.operands[0].value.reg)
    op2 = inst.reg_name(inst.operands[1].value.reg)
    op3 = inst.operands[2]
    print "0x%x:\t%s\t%s\t(%s := %s | 0x%08x)" %(inst.address, inst.mnemonic, inst.op_str, op1, op2, op3.value.imm)

def ProcessAnd(inst):
    op1 = inst.reg_name(inst.operands[0].value.reg)
    op2 = inst.reg_name(inst.operands[1].value.reg)
    op3 = inst.operands[2]
    print "0x%x:\t%s\t%s\t(%s := %s & 0x%08x)" %(inst.address, inst.mnemonic, inst.op_str, op1, op2, op3.value.imm)

def ProcessMov(inst):
    op1 = inst.reg_name(inst.operands[0].value.reg)
    if inst.operands[1].type == ARM_OP_IMM:
        op2 = inst.operands[1].value.imm
        print "0x%x:\t%s\t%s\t(%s := 0x%08x)" %(inst.address, inst.mnemonic, inst.op_str, op1, op2)
    else:
        op2 = inst.reg_name(inst.operands[1].value.reg)
        print "0x%x:\t%s\t%s\t(%s := %s & 0x%08x)" %(inst.address, inst.mnemonic, inst.op_str, op1, op2)

def ProcessInstruction(inst):
    if inst.mnemonic == "b":
        ProcessBranch(inst)
    elif inst.mnemonic == "bl":
        ProcessBranchLong(inst)
    elif inst.mnemonic == "bic":
        ProcessBitClear(inst)
    elif inst.mnemonic == "orr":
        ProcessOrr(inst)
    elif inst.mnemonic == "and":
        ProcessAnd(inst)
    elif inst.mnemonic == "mov":
        ProcessMov(inst)
    else:
        ProcessDefault(inst)


################################################################################
# Open the input file
with open(sys.argv[2]) as f:
    data = bytearray(f.read())

# Set the chunksize and other parameters
chunksize = 16
baseaddress = 0xC0000000

# Pad the input file data to a multiple of chunksize
length = len(data)
fraglength = chunksize - (length % chunksize)
data.extend(bytearray(fraglength))
CODE = bytes(data)
length = len(data)

length = 256

md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
md.detail = True
for offset in range(0, length, chunksize):
    chunk = CODE[offset:offset+chunksize]
    for inst in md.disasm(chunk, baseaddress+offset):
        ProcessInstruction(inst)


