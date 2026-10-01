#!/usr/bin/env python3
"""A minimal SMTP sink: writes each received message to a file, then exits."""
import socket
import sys
import threading

PORT = int(sys.argv[1])
OUT = sys.argv[2]

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(8)
print("listening %d" % PORT, flush=True)


def handle(conn):
    f = conn.makefile("rwb", buffering=0)
    f.write(b"220 smtpsink ESMTP\r\n")
    data_mode = False
    msg = []
    while True:
        line = f.readline()
        if not line:
            break
        if data_mode:
            if line.strip() == b".":
                data_mode = False
                with open(OUT, "ab") as out:
                    out.write(b"".join(msg) + b"\n--- END ---\n")
                msg = []
                f.write(b"250 2.0.0 Ok: queued\r\n")
            else:
                msg.append(line)
            continue
        cmd = line.strip().upper()
        if cmd.startswith(b"EHLO"):
            f.write(b"250-smtpsink\r\n250 8BITMIME\r\n")
        elif cmd.startswith(b"HELO"):
            f.write(b"250 smtpsink\r\n")
        elif cmd.startswith((b"MAIL", b"RCPT")):
            f.write(b"250 2.1.0 Ok\r\n")
        elif cmd.startswith(b"DATA"):
            data_mode = True
            f.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        elif cmd.startswith(b"RSET"):
            f.write(b"250 Ok\r\n")
        elif cmd.startswith(b"QUIT"):
            f.write(b"221 Bye\r\n")
            break
        else:
            f.write(b"250 Ok\r\n")
    conn.close()


while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
