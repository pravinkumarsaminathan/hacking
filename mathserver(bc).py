from subprocess import PIPE,Popen,STDOUT
from threading import Thread
import socket

class ProcessOutputThread(Thread):
    def __init__(self,p,c,a):
        Thread.__init__(self)
        self.p = p
        self.c = c
        self.a = a
    
    def run(self):
        while self.p.poll() is None:
            try:
                self.c.sendall(self.p.stdout.readline())
            except:
                print("Connection reset for {}".format(self.a[0]))
                con.remove(self.a[0])
            

class MathsServerThread(Thread):
    def __init__(self,conn,addr):
        Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        
    def run(self):
        p = Popen(['bc', '-q'],stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        out_t = ProcessOutputThread(p,self.conn)
        out_t.start()
        while p.poll() is None:
            try:
                inp = self.conn.recv(1024)
                inp = inp.decode('ISO-8859-1').strip()
                if not inp:
                    break
                elif inp == "quit" or inp == "exit":
                    p.kill()
                    break
                    self.conn.close()
                inp = inp + "\n"
                p.stdin.write(inp.encode())
                p.stdin.flush()
            except Exception as e:
                print(str(addr[0]) + "-" + str(e))
                self.conn.close()
                con.remove(self.addr[0])
    
HOST = ""
PORT = 7890
con = []

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
s.bind((HOST,PORT))
s.listen()
while True:
    conn, addr = s.accept()
    if addr[0] in con:
        print("Connection Rejected from {} : {}".format(addr[0],addr[1]))
        conn.close()
    else:
        con.append(addr[0])
        print("Connection Accepted from {} : {}".format(addr[0],addr[1]))
        t = MathsServerThread(conn,addr)
        t.start()