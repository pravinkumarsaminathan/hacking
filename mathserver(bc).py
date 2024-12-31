from subprocess import PIPE,Popen,STDOUT
from threading import Thread
import socket
import time
from threading import Lock

class TokenBucket:
    def __init__(self, rate, capacity):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = Lock()

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now

    def allow_request(self):
        with self.lock:
            self._refill()
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

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
    def __init__(self,conn,addr,bucket):
        Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        self.bucket = bucket
    
    def run(self):
        p = Popen(['bc', '-q'],stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        out_t = ProcessOutputThread(p,self.conn,self.addr)
        out_t.start()
        while p.poll() is None:
            try:
                inp = self.conn.recv(1024)
                inp = inp.decode('ISO-8859-1').strip()
                if not inp:
                    break
                elif inp == "quit" or inp == "exit":
                    p.kill()
                    self.conn.close()
                    break
                #firewall for limit input digit
                if '^' in inp:
                    flag = 0
                    result = str(inp).split('^')
                    if (len(result) < 3):
                        if len(result[1]) > 4:
                            flag = 1
                        if len(result[0]) > 20:
                            flag = 1
                    else:
                        if (len(inp) > 5) or (int(result[0]) > 9 or int(result[1]) > 9 or int(result[2]) > 6):
                            flag = 1
                    if (flag == 1):
                        self.conn.sendall("The server can't allow large input.! firewall implemented /_\ \n".encode())
                        continue
                #firewall for request rate limit
                if self.bucket.allow_request():
                    print("Request allowed")
                    inp = inp + "\n"
                    p.stdin.write(inp.encode())
                    p.stdin.flush()
                else:
                    print("Rate limit exceeded")
                    self.conn.sendall("Request rate excited try after 10 sec. firewall implemented /_\ \n".encode())
                    continue
                    
            except Exception as e:
                print(str(addr[0]) + "-" + str(e))
                self.conn.close()
                con.remove(self.addr[0])
HOST = ""
PORT = 7890
con = []
bucket = TokenBucket(rate=0.833, capacity=50)

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
        t = MathsServerThread(conn,addr,bucket)
        t.start()
