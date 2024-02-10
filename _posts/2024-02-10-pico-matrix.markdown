---
layout: posts
title:  "PicoCTF M A T R I X"
date:   2024-02-10 14:56:00 +0100
---
*This one was really tough, but cool af.*

Analyzing binary we can simple see the main function runs  a while loop of another function which uses some bytes as arguments.

By further analysis we found out it is custom assembly so we have to decode the bytes and what they do.

From the function that is being run in a while loop:
```c
undefined8 step(state *state,exitc *out)

{
  undefined *bVar8;
  ushort cur-ip;
  ushort next-ip;
  byte *puVar1;
  byte cur-code;
  long lVar4;
  ushort *psVar5;
  short sVar1;
  undefined uVar1;
  
  lVar4 = state->code;
  cur-ip = state->ip;
  next-ip = cur-ip + 1;
  state->ip = next-ip;
  cur-code = *(byte *)(lVar4 + (ulong)cur-ip);
  switch(cur-code) {
  case 0:
    break;
  case 1:
    if (out == (exitc *)0x0) {
      return 0;
    }
    psVar5 = state->stack;
    *(undefined *)out = 0;
    cur-ip = psVar5[-1];
    state->stack = psVar5 + -1;
    out->exit = cur-ip;
    return 0;
  case 0x10:
    psVar5 = state->stack;
    cur-ip = psVar5[-1];
    state->stack = psVar5 + 1;
    *psVar5 = cur-ip;
    return 1;
  case 0x11:
    state->stack = state->stack + -1;
    return 1;
  case 0x12:
    psVar5 = state->stack;
    next-ip = psVar5[-1];
    cur-ip = psVar5[-2];
    state->stack = psVar5 + -1;
    psVar5[-2] = next-ip + cur-ip;
    return 1;
  case 0x13:
    psVar5 = state->stack;
    next-ip = psVar5[-2];
    cur-ip = psVar5[-1];
    state->stack = psVar5 + -1;
    psVar5[-2] = next-ip - cur-ip;
    return 1;
  case 0x14:
    psVar5 = state->stack;
    cur-ip = psVar5[-2];
    psVar5[-2] = psVar5[-1];
    state->stack = psVar5;
    psVar5[-1] = cur-ip;
    return 1;
  case 0x20:
    psVar5 = state->stack;
    state->stack = psVar5 + -1;
    cur-ip = psVar5[-1];
    psVar5 = state->alt_stack;
    state->alt_stack = psVar5 + 1;
    *psVar5 = cur-ip;
    return 1;
  case 0x21:
    puVar1 = (byte *)state->alt_stack;
    state->alt_stack = (undefined2 *)(puVar1 + -2);
    cur-ip = *(ushort *)(puVar1 + -2);
    psVar5 = state->stack;
    state->stack = psVar5 + 1;
    *psVar5 = cur-ip;
    return 1;
  case 0x30:
    cur-ip = state->stack[-1];
    state->stack = state->stack + -1;
    state->ip = cur-ip;
    return 1;
  case 0x31:
    psVar5 = state->stack;
    next-ip = psVar5[-2];
    cur-ip = psVar5[-1];
    state->stack = psVar5 + -2;
    if (next-ip == 0) {
LAB_0010154b:
      state->ip = cur-ip;
      return 1;
    }
    break;
  case 0x32:
    psVar5 = state->stack;
    next-ip = psVar5[-2];
    cur-ip = psVar5[-1];
    state->stack = psVar5 + -2;
    if (next-ip != 0) goto LAB_0010154b;
    break;
  case 0x33:
    psVar5 = state->stack;
    next-ip = psVar5[-2];
    cur-ip = psVar5[-1];
    state->stack = psVar5 + -2;
    if ((short)next-ip < 0) goto LAB_0010154b;
    break;
  case 0x34:
    psVar5 = state->stack;
    next-ip = psVar5[-2];
    cur-ip = psVar5[-1];
    state->stack = psVar5 + -2;
    if ((short)next-ip < 1) goto LAB_0010154b;
    break;
  default:
    if (cur-code == 0xc0) {
      bVar8._0_1_ = (*(code *)state->getc_stdin)();
      psVar5 = state->stack;
      state->stack = psVar5 + 1;
      *psVar5 = (ushort)(byte)bVar8;
      return 1;
    }
    if (cur-code < 0xc1) {
      if (cur-code == 0x80) {
        sVar1 = 2;
        next-ip = (ushort)*(char *)(lVar4 + (ulong)next-ip);
      }
      else {
        if (cur-code != 0x81) goto switchD_0010137b_caseD_2;
        sVar1 = 3;
        next-ip = *(ushort *)(lVar4 + (ulong)next-ip);
      }
      psVar5 = state->stack;
      state->ip = cur-ip + sVar1;
      state->stack = psVar5 + 1;
      *psVar5 = next-ip;
      return 1;
    }
    if (cur-code == 0xc1) {
      uVar1 = *(undefined *)(state->stack + -1);
      state->stack = state->stack + -1;
      (*(code *)state->putc_stdout)(uVar1);
      return 1;
    }
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
  case 8:
  case 9:
  case 10:
  case 0xb:
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
  case 0x15:
  case 0x16:
  case 0x17:
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
  case 0x22:
  case 0x23:
  case 0x24:
  case 0x25:
  case 0x26:
  case 0x27:
  case 0x28:
  case 0x29:
  case 0x2a:
  case 0x2b:
  case 0x2c:
  case 0x2d:
  case 0x2e:
  case 0x2f:
switchD_0010137b_caseD_2:
    if (out == (exitc *)0x0) {
      return 0;
    }
    *(undefined *)out = 1;
    return 0;
  }
  return 1;
}
```

We can dissasemble it like:
```c
case 0: NOP
case 1: POP (EXIT)
case 0x10: DUP
case 0x11: POP
case 0x12: ADD (from stack)
case 0x13: SUB (from stack)
case 0x14: SWP (from stack)
case 0x20: TO_ALT_STACK (pop value and push on alt)
case 0x21: FROM_ALT
case 0x30: POP_JMP
case 0x31: JMP_IF_ZERO
case 0x32: JMP_IF_NOT_ZERO
case 0x33: JMP_BELOW_ZERO
case 0x34: JMP_BELOW_ONE
case 0xc0: GET_STDIN
case 0x80: PUSH1
case 0x81: PUSH2
case 0xc1: PUT_CHAR

```

From this we can create a python script to simulate the program at runtime:
```python

code = '81 75 00 80 00 80 0a 80 3f 80 65 80 76 80 69 80 6c 80 61 80 20 80 74 80 75 80 6f 80 20 80 74 80 69 80 20 80 65 80 6b 80 61 80 6d 80 20 80 75 80 6f 80 79 80 20 80 6e 80 61 80 43 80 0a 80 58 80 20 80 49 80 20 80 52 80 20 80 54 80 20 80 41 80 20 80 4d 80 20 80 65 80 68 80 74 80 20 80 6f 80 74 80 20 80 65 80 6d 80 6f 80 63 80 6c 80 65 80 57 81 3b 01 30 80 01 80 01 80 00 c0 10 80 75 13 81 a0 00 31 10 80 64 13 81 aa 00 31 10 80 6c 13 81 b4 00 31 10 80 72 13 81 c0 00 31 81 fb 00 30 11 20 80 01 13 21 81 cc 00 30 11 20 80 01 12 21 81 cc 00 30 11 20 20 80 01 13 21 21 81 cc 00 30 11 20 20 80 01 12 21 21 81 cc 00 30 20 20 81 da 00 21 10 20 80 10 81 47 01 30 14 10 20 12 21 14 21 14 21 14 20 81 ef 00 21 80 02 81 61 01 30 81 7b 00 14 81 74 01 12 30 80 00 01 81 38 01 80 00 80 0a 80 2e 80 65 80 75 80 72 80 67 80 20 80 61 80 20 80 79 80 62 80 20 80 6e 80 65 80 74 80 61 80 65 80 20 80 65 80 72 80 65 80 77 80 20 80 75 80 6f 80 59 81 3b 01 30 80 01 01 10 81 45 01 31 c1 81 3b 01 30 11 30 80 00 20 20 10 81 5b 01 31 80 01 13 21 10 21 12 81 49 01 30 11 21 11 21 14 30 10 81 71 01 31 80 01 13 20 10 12 21 81 61 01 30 11 14 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 81 7f 05 30 81 fb 00 30 30 00 00 00 81 fb 00 30 81 7f 05 30 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 74 05 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 74 05 30 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 7f 05 30 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 30 00 00 00 81 74 05 30 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 30 00 00 00 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 30 00 00 00 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 81 fb 00 30 81 74 05 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 30 00 00 00 81 fb 00 30 30 00 00 00 30 00 00 00 30 00 00 00 30 00 00 00 81 fb 00 30 30 00 00 00 30 00 00 00 81 74 05 30 30 00 00 00 81 fb 00 30 30 00 00 00 30 00 00 00 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 fb 00 30 81 85 05 30 81 fb 00 30 20 10 81 fb 00 31 80 01 13 21 30 20 80 01 12 21 30 11 11 11 11 81 ce 05 80 00 80 0a 80 21 80 74 80 69 80 20 80 65 80 64 80 61 80 6d 80 20 80 75 80 6f 80 79 80 20 80 2c 80 73 80 6e 80 6f 80 69 80 74 80 61 80 6c 80 75 80 74 80 61 80 72 80 67 80 6e 80 6f 80 43 81 3b 01 30 81 f8 00 30'

code = code.split(" ")

class Stack:
    def __init__(self):
        self.stack = []
    def push(self, val):
        self.stack.append(val)
    def pop(self):
        return self.stack.pop()

stack = Stack()
alt_stack = Stack()


ops = {
    "00": ["NOP", "No operation"],
    "01": ["EXT", "Set exit code and exit"],
    "10": ["DUP", "Duplicate"],
    "11": ["POP", "Pop off stack"],
    "12": ["ADD", "add"],
    "13": ["SUB", "subtract"],
    "14": ["SWP", "swap"],
    "20": ["TAL", "to other stack (to alt)"],
    "21": ["FAL", "from other stack (from alt)"],
    "30": ["JMP", "jump to value and pop off stack"],
    "31": ["JIZ", "jump if zero"],
    "32": ["JIN", "jump if not zero"],
    "33": ["JIL", "jump if less than zero"],
    "34": ["JIO", "jump if less than one"],
    "80": ["GOB", "get a byte from code and put it on stack"],
    "81": ["GTB", "get 2 bytes from code and put them on stack"],
    "c1": ["OUT", "pops a value and prints it"],
    "c0": ["INP", "inputs a character and puts it on the stack"]
}

output = ""

ct = 0
while ct < len(code):
    if code[ct] in ops.keys():
        print(f"{ct:03x}", ops[code[ct]][0], end= " ")
        if ops[code[ct]][0] == "GOB":
            ct += 1
            stack.push("00" + code[ct])
            print("00" + code[ct])
        elif ops[code[ct]][0] == "GTB":
            r = []
            ct += 1
            r.append(code[ct])
            ct += 1
            r.append(code[ct])
            stack.push("".join(reversed(r)))
            print("".join(reversed(r)))
        elif ops[code[ct]][0] == "EXT":
            print(stack.pop())
            break
        elif ops[code[ct]][0] == "DUP":
            r = stack.pop()
            stack.push(r)
            stack.push(r)
            print(r)
        elif ops[code[ct]][0] == "POP":
            stack.pop()
            print()
        elif ops[code[ct]][0] == "ADD":
            a = stack.pop()
            b = stack.pop()
            print(a, ",", b)
            if hex(int(a, 16) + int(b, 16)).startswith("-0x"):
                stack.push("-" + hex(int(b, 16) + int(a, 16))[3:])
            else:
                stack.push(hex(int(b, 16) + int(a, 16))[2:])
        elif ops[code[ct]][0] == "SUB":
            a = stack.pop()
            b = stack.pop()
            print(b, ",", a)
            if hex(int(b, 16) - int(a, 16)).startswith("-0x"):
                stack.push("-" + hex(int(b, 16) - int(a, 16))[3:])
            else:
                stack.push(hex(int(b, 16) - int(a, 16))[2:])
        elif ops[code[ct]][0] == "SWP":
            a = stack.pop()
            b = stack.pop()
            print(a, ",", b)
            stack.push(a)
            stack.push(b)
        elif ops[code[ct]][0] == "TAL":
            r = stack.pop()
            alt_stack.push(r)
            print(r)
        elif ops[code[ct]][0] == "FAL":
            r = alt_stack.pop()
            stack.push(r)
            print(r)
        elif ops[code[ct]][0] == "JMP":
            ct = int(stack.pop(), 16) - 1
            print(f"{ct+1:03x}")
            # print()
        elif ops[code[ct]][0] == "JIZ":
            jump = stack.pop()
            check = stack.pop()
            if (int(check, 16) == 0):
                ct = int(jump, 16) - 1
                pass
            print(f"{ct+1:03x}")
            # print()
        elif ops[code[ct]][0] == "JIN":
            jump = stack.pop()
            check = stack.pop()
            if (int(check, 16) != 0):
                ct = int(jump, 16) - 1
                pass
            print(f"{ct+1:03x}")
            # print()
        elif ops[code[ct]][0] == "JIL":
            jump = stack.pop()
            check = stack.pop()
            if (int(check, 16) < 0):
                ct = int(jump, 16) - 1
                pass
            print(f"{ct+1:03x}")
            # print()
        elif ops[code[ct]][0] == "JIO":
            jump = stack.pop()
            check = stack.pop()
            if (int(check, 16) < 1):
                ct = int(jump, 16) - 1
                pass
            print(f"{ct+1:03x}")
            # print()
        elif ops[code[ct]][0] == "OUT":
            out = stack.pop()
            print(chr(int(out, 16)))
            output += chr(int(out, 16))
        elif ops[code[ct]][0] == "INP":
            stack.push(hex(ord(input()))[2:])

        else:
            print()
        print(stack.stack)
    ct += 1
print(output)

```

---
Now comes the harder part...

With dynamic analysis from out written disassembler, we can assume that program checks our input against four letters and jmp based on that

```
07b INP a  
['0001', '0001', '0000', '61']  
07c DUP 61  
['0001', '0001', '0000', '61', '61']  
07d GOB 0075  
['0001', '0001', '0000', '61', '61', '0075']  
07f SUB 61 , 0075  
['0001', '0001', '0000', '61', '-14']  
080 GTB 00a0  
['0001', '0001', '0000', '61', '-14', '00a0']  
083 JIZ 084  
['0001', '0001', '0000', '61']  
084 DUP 61  
['0001', '0001', '0000', '61', '61']  
085 GOB 0064  
['0001', '0001', '0000', '61', '61', '0064']  
087 SUB 61 , 0064  
['0001', '0001', '0000', '61', '-3']  
088 GTB 00aa  
['0001', '0001', '0000', '61', '-3', '00aa']  
08b JIZ 08c  
['0001', '0001', '0000', '61']  
08c DUP 61  
['0001', '0001', '0000', '61', '61']  
08d GOB 006c  
['0001', '0001', '0000', '61', '61', '006c']  
08f SUB 61 , 006c  
['0001', '0001', '0000', '61', '-b']  
090 GTB 00b4  
['0001', '0001', '0000', '61', '-b', '00b4']  
093 JIZ 094  
['0001', '0001', '0000', '61']  
094 DUP 61  
['0001', '0001', '0000', '61', '61']  
095 GOB 0072  
['0001', '0001', '0000', '61', '61', '0072']  
097 SUB 61 , 0072  
['0001', '0001', '0000', '61', '-11']  
098 GTB 00c0  
['0001', '0001', '0000', '61', '-11', '00c0']  
09b JIZ 09c  
['0001', '0001', '0000', '61']
```

If we don't enter any of these four characters(r,l,u,d) the program will exit.

The `r l u d` characters imply that we may be dealing with some 2d game
based on `r = right, l = left, u = up, d = down`

I tried looking at a code and try to understand it but I ended up with nothing, cuz the custom VM is based entirely on stack so it was really hard for me to understand.



Therefore I tried different approach with dynamic analysis:

I found out that the program stores our position onto a stack:

first input `r`:

![stack value r](/assets/images/Pasted%20image%2020240209162342.png)

first input `l`:

![stack-values-l](/assets/images/Pasted image 20240209162502.png)

Another finding was that:

If we enter the right input the program prompts user asking for another character. 

If we enter the wrong one the program just exits.



Therefore I tried to compare these two situations.
Using online string compare tool I found that the program runs basically the same most of the time for both cases(right/wrong) up until a certain point.

![string-compare](/assets/images/Pasted image 20240209162557.png)

Looking back on how program calculated these jump values, we found out it calculates them from current position:
`VALUE = JMP_OFF + (0x10*y+x)*4`

JMP_OFF is always `0x174`

Therefore I dumped all bytes from `0x174` till the end:

![dump](/assets/images/Pasted image 20240209165045.png)

Here we see bunch of reapeting sequences so lets substitute them. We can find from the analysis that `81fb0030` are bytes that lead to exit.

so lets substitute and split to lines by `0x40` bytes (based on calculation of value):
```
81fb0030 = #
30000000 = _
```
there are still some sequences which doesn't exit the program, but we don't know what they actually do:
```
817f0530 = ?
81740530 = !
```

![maze1](/assets/images/Pasted image 20240209165751.png)

It looks like a maze so lets try to solve it: 

(We start at 1,1)

If we take `rrrd` the program exits on reaching `!` cell, even though this is the only place from which we can exit the first "cell" 
We can take the `rrrrrlld` route and the program doesn't exit, implying that we must visit the `?` cell before visiting `!`

So what happened?
By analysis we can see the program tracks three values:

![health-on-stack](/assets/images/Pasted image 20240209170039.png)

We know first two are (x, y) coordinates, but what is the third one?

Upon visiting `?` cell it increases by one on each visit and upon visiting `!` cell it decreases by one... We can surely assume this is some kind of health.

Lets rename to something more readable like `? = +` and `! = -`

![maze2](/assets/images/Pasted image 20240209170355.png)

And we can try to solve now, by stacking health on the first + and then walking through the maze. Aaand voilà we get the flag.


