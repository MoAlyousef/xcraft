from pwn import *

context.binary = './bin/vuln'         
elf = context.binary
rop = ROP(elf)

for addr, g in sorted(rop.gadgets.items()):
    print(f"0x{addr:016x}", end='')
    for insn in g.insns:
        print(f" {insn};", end='')
    print()

g = rop.find_gadget(['pop rdi', 'ret'])
if g:
    print(f"0x{g.address:016x}")

matches = [addr for addr, g in rop.gadgets.items() if g.insns == ['pop rdi', 'ret']]
for a in sorted(matches):
    print(f"0x{a:016x}")