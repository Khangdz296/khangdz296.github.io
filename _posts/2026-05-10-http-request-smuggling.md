---
title: HTTP Request Smuggling
date: 2026-05-10 10:00:00 +0700
categories: [Web Security, PortSwigger]
tags: [http-request-smuggling, desync, portswigger, writeup]
---

## 1. HTTP Request Smuggling là gì? Tại sao nó tồn tại?

Trong các kiến trúc web hiện đại, người dùng hiếm khi giao tiếp trực tiếp với máy chủ chứa ứng dụng (Back-end server). Thay vào đó, các request sẽ đi qua một hoặc nhiều lớp trung gian (Front-end server) như Reverse Proxy, Load Balancer, hay WAF.

Vấn đề cốt lõi của **HTTP Request Smuggling** xảy ra khi Front-end server và Back-end server có **cách hiểu khác nhau về ranh giới của một HTTP Request**. Khi kẻ tấn công gửi một request mập mờ, Front-end có thể nghĩ đó là một request duy nhất, nhưng Back-end lại hiểu đó là hai request ghép lại. Phần "dư thừa" của request đầu tiên sẽ bị smuggled và dính chặt vào phần đầu của request hợp lệ tiếp theo do một người dùng bất kỳ gửi tới. Hệ quả là kẻ tấn công có thể can thiệp, đánh cắp dữ liệu, hoặc leo thang đặc quyền.

## 2. Sự bất đồng giữa Front-end và Back-end

Để hiểu cách tạo ra một payload smuggling, chúng ta cần nắm rõ hai yếu tố quan trọng ảnh hưởng đến kích thước và cách đọc gói tin.

### 2.1. Cách tính độ dài Request: Content-Length (CL) vs Transfer-Encoding (TE)

Theo chuẩn HTTP/1.1, có hai cách chính để xác định phần thân (body) của request kết thúc ở đâu:

- **Content-Length (CL):** Khai báo chính xác tổng số byte của phần Request Body. Chú ý rằng các ký tự ngắt dòng `\r\n` (CRLF) cũng được tính là 2 byte. Như trong công cụ Inspector của Burp Suite, khi bạn bôi đen một đoạn text, nó sẽ hiện số byte.

![image.png](/assets/img/20260510-http-request-smuggling/image.png)

- **Transfer-Encoding: chunked (TE):** Dữ liệu được gửi đi theo từng khối (chunk). Mỗi khối bắt đầu bằng một số **Hexadecimal** (thập lục phân) chỉ định kích thước của khối đó (ví dụ: `a0` tương đương 160 bytes, hoặc `4` tương đương 4 bytes), theo sau là `\r\n`, rồi đến nội dung khối, và kết thúc bằng `\r\n`.

![image.png](/assets/img/20260510-http-request-smuggling/image%201.png)

- **Ký hiệu kết thúc:** Máy chủ sử dụng TE sẽ ngừng đọc khi gặp một khối có kích thước bằng `0` (nghĩa là `0\r\n\r\n`).

Lỗ hổng xảy ra khi ta gửi cả hai header này cùng lúc, và cấu hình server khiến Front-end ưu tiên CL còn Back-end ưu tiên TE, hoặc ngược lại. Với CL.TE, Back-end dừng đọc tại chunk `0`, khiến dữ liệu phía sau bị treo lại trong pipeline. Với TE.CL, Front-end chuyển tiếp body theo chunked encoding, nhưng Back-end chỉ đọc đúng số byte trong `Content-Length`, khiến phần body còn lại trở thành smuggled request cho request tiếp theo.

## 3. Các dạng lỗ hổng HTTP Request Smuggling cơ bản

### 3.1. Lỗ hổng CL.TE (Front-end ưu tiên Content-Length, Back-end ưu tiên Transfer-Encoding)

**Cơ chế hoạt động:** Lỗ hổng này xảy ra khi máy chủ Front-end xác định độ dài gói tin dựa trên header `Content-Length`, nhưng máy chủ Back-end lại đọc gói tin theo `Transfer-Encoding: chunked`.

Front-end sẽ đẩy toàn bộ dữ liệu đi theo đúng số byte khai báo ở CL. Tuy nhiên, khi luồng dữ liệu này đến Back-end, Back-end xử lý theo dạng chunked và sẽ **dừng đọc ngay lập tức khi gặp một chunk có kích thước bằng `0`**. Phần dữ liệu nằm sau số `0` này bị bỏ lại trong pipeline và trở thành phần đầu của request hợp lệ tiếp theo.

### **3.2. Lỗ hổng TE.CL (Front-end ưu tiên Transfer-Encoding, Back-end ưu tiên Content-Length)**

**Cơ chế hoạt động:** Đảo ngược lại với kịch bản trên, ở đây Front-end xử lý request theo `Transfer-Encoding: chunked` và chuyển tiếp toàn bộ các khối dữ liệu cho đến khi gặp chunk `0\r\n\r\n`. Nhưng Back-end lại chỉ đọc theo `Content-Length`. Kẻ tấn công cố tình thiết lập giá trị CL rất nhỏ để Back-end ngừng nhận dữ liệu sớm hơn thực tế, bỏ mặc phần còn lại của body lơ lửng trong hệ thống để giả mạo request sau.

#### **Write-up Lab: HTTP request smuggling, basic TE.CL vulnerability**

**Mô tả đề bài:** Hệ thống mục tiêu bao gồm máy chủ Front-end và Back-end. Điểm cốt lõi là máy chủ Front-end hỗ trợ và ưu tiên xử lý dữ liệu theo dạng chunked (`Transfer-Encoding`), trong khi máy chủ Back-end lại không hỗ trợ tính năng này và chỉ dựa vào `Content-Length`. Front-end có cơ chế chặn các request không dùng phương thức GET hoặc POST. Nhiệm vụ của chúng ta là bypass cơ chế chặn này bằng cách smuggle một request khiến Back-end tin rằng nó đang nhận được một phương thức mang tên `GPOST`.

![image.png](/assets/img/20260510-http-request-smuggling/image%202.png)

**Quá trình thực thi (Cách Payload hoạt động):**

1. **Vượt qua Front-end (TE):** 
    - Khi gửi request này, Front-end ưu tiên đọc theo header `Transfer-Encoding: chunked`.
    - Nó thấy chunk đầu tiên có kích thước là `62` (mã Hex, tương đương 98 bytes decimal), bao trọn toàn bộ đoạn từ chữ `G` của `GPOST` cho đến hết cụm `hihi=helo\r\n`.
    - Kế tiếp, nó gặp chunk `0` (ký hiệu kết thúc).
    - Do đúng chuẩn định dạng chunked, Front-end coi đây là một request hợp lệ hoàn chỉnh và luân chuyển **toàn bộ** luồng dữ liệu này về phía Back-end.
2. **Gây lú cho Back-end (CL):**
    - Máy chủ Back-end nhận được luồng dữ liệu nhưng nó không hiểu `Transfer-Encoding`. Nó quay sang đọc `Content-Length: 4` mà ta đã cố tình set nhỏ lại.
    - Back-end sẽ chỉ đọc đúng **4 bytes đầu tiên** của phần Body. 4 bytes này chính là: ký tự `6`, ký tự `2`, và ký hiệu ngắt dòng `\r\n`.
    - Ngay sau 4 bytes này, Back-end dừng đọc, coi như đã xử lý xong request đầu tiên (và trả về mã `200 OK` ở bên Response).
3. **Smuggled Request:**
    - Toàn bộ phần dữ liệu còn lại (bắt đầu từ `GPOST...` cho đến hết số `0`) không hề biến mất. Nó bị treo lại trong hàng đợi (pipeline) của hệ thống mạng.
    - Lúc này, đoạn mã độc đã nằm chờ sẵn như một quả bom nổ chậm.
4. **Thực thi:**
    - Khi một người dùng bình thường khác gửi request hợp lệ tiếp theo đến máy chủ (ví dụ: thao tác F5 lại trang trên trình duyệt).
    - Request mới này khi đi vào Back-end sẽ ngay lập tức bị nối đuôi vào đoạn mã độc đang treo chờ sẵn.
    - Back-end xử lý đoạn mã đó và thấy nó bắt đầu bằng `GPOST / HTTP/1.1`. Do phương thức `GPOST` không tồn tại trong chuẩn HTTP, Back-end ngay lập tức văng ra lỗi: **`Unrecognized method GPOST`**.

![image.png](/assets/img/20260510-http-request-smuggling/image%203.png)

### **3.3. Kỹ thuật làm rối (Obfuscating) Header Transfer-Encoding (TE.TE behavior)**

**Cơ chế hoạt động:** Trường hợp này phức tạp hơn vì cả Front-end và Back-end đều hỗ trợ `Transfer-Encoding`. Để tạo ra sự bất đồng bộ, kẻ tấn công phải chèn nhiều header TE hoặc thay đổi, làm biến dạng header TE đi một chút (obfuscation). Một trong hai máy chủ sẽ không nhận diện được header bị làm rối, do đó nó lùi về (fallback) sử dụng `Content-Length`. Máy chủ còn lại vẫn nhận ra chuẩn TE bình thường. Tùy thuộc vào máy chủ nào bị đánh lừa, lỗ hổng sẽ biến thành CL.TE hoặc TE.CL.

#### **Write-up Lab: HTTP request smuggling, obfuscating the TE header**

![image.png](/assets/img/20260510-http-request-smuggling/image%204.png)

**Mô tả đề bài:** Hai máy chủ Front-end và Back-end có cách xử lý khác nhau khi gặp các header HTTP trùng lặp. Front-end được cấu hình để từ chối các request không sử dụng phương thức GET hoặc POST. Yêu cầu của bài lab là smuggle một request sao cho request tiếp theo được Back-end xử lý sẽ bị biến thành phương thức `GPOST` (một phương thức không hợp lệ). 

![image.png](/assets/img/20260510-http-request-smuggling/image%205.png)

**Quá trình thực thi:**

1. Thực hiện gửi cùng lúc hai header TE nhằm gây nhiễu: `Transfer-Encoding: x` và `Transfer-Encoding: chunked`.  

2. Một máy chủ không xử lý được TE bị làm rối nên sử dụng `Content-Length: 105`, đẩy trọn vẹn toàn bộ payload. Máy chủ kia vẫn hiểu đây là chunked encoding nên dừng đọc tại khối `0`.  

3. Phần độc hại bị buôn lậu là một request hoàn chỉnh bắt đầu bằng `GPOST / HTTP/1.1` cùng với khai báo độ dài `Content-Length: 15`.  

4. Khi request tiếp theo của người dùng (bắt đầu bằng POST hoặc GET) đến, nó nối thẳng vào phần body của `GPOST`. Back-end cố gắng thực thi và ngay lập tức ném ra lỗi `Unrecognized method GPOST`. Qua đó, ta đã chứng minh được mình đã bypass thành công cơ chế chặn method của Front-end.

![image.png](/assets/img/20260510-http-request-smuggling/image%206.png)

## 4. Phương pháp nhận diện và xác nhận lỗ hổng

### **4.1. Kỹ thuật Time-delay**

Đây là bước Recon đầu tiên và an toàn nhất. Kỹ thuật này thường được dùng để tìm các lỗ hổng CL.TE bằng cách sử dụng kỹ thuật tính thời gian.

**Cơ chế phát hiện CL.TE bằng Timing:** Ta gửi một request chứa cả header CL và TE. Front-end ưu tiên CL nên chuyển tiếp request. Tuy nhiên, ta cố tình làm sai lệch định dạng chunked để đánh lừa Back-end (nơi ưu tiên TE).
Thay vì gửi một chunk hoàn chỉnh kèm chunk `0` kết thúc, ta gửi một payload khai báo chunk có kích thước lớn nhưng lại không gửi đủ dữ liệu, hoặc không gửi chunk `0`. Khi đó, Back-end sẽ treo kết nối để chờ đợi phần dữ liệu còn thiếu. Kết quả là máy chủ sẽ bị delay một khoảng thời gian đáng kể (thường là vài giây cho đến khi timeout) trước khi trả về phản hồi. Nếu quan sát thấy độ trễ này, đây là tín hiệu mạnh cho thấy cần kiểm tra tiếp bằng kỹ thuật differential response để xác nhận lỗ hổng.

**Cơ chế phát hiện TE.CL bằng Timing:** Tương tự, ta cấu hình để Front-end đọc TE và luân chuyển bình thường. Nhưng ở Back-end (ưu tiên CL), ta set giá trị CL lớn hơn số lượng byte thực tế của body. Back-end sẽ đứng chờ số byte còn lại được gửi tới, tạo ra độ trễ (delay) tương tự.

### **4.2. Kỹ thuật phản hồi khác biệt**

Mục tiêu của việc xác nhận các lỗ hổng bảo mật CL.TE (hoặc TE.CL) bằng cách sử dụng phản hồi khác biệt là ta sẽ giả mạo một đoạn request cố tình chọc vào một endpoint không tồn tại (ví dụ: `GET /404`).

Ta gửi request bị lỗi này vào hệ thống sao cho nó treo lại ở Back-end. Ngay lập tức sau đó, ta gửi một request bình thường hợp lệ, giả sử là request gọi vào thư mục gốc (`/`).  

**Nếu hệ thống an toàn:** Request thứ hai sẽ nhận về mã `200 OK` (vì truy cập vào trang chủ `/`).

**Nếu lỗ hổng tồn tại:** Request thứ hai bị dính chặt vào cái đuôi `GET /404` đang trực chờ sẵn. Kết quả là Back-end tìm kiếm trang `/404` và trả về mã lỗi `404 Not Found`.

Sự thay đổi phản hồi đột ngột của một request hoàn toàn bình thường chính là bằng chứng đanh thép xác nhận hệ thống có lỗ hổng.

#### **Write-up Lab: HTTP request smuggling, confirming a CL.TE vulnerability via differential responses**

**Mô tả đề bài:** Hệ thống có máy chủ Front-end và Back-end, trong đó Front-end không hỗ trợ chunked encoding. Để giải quyết bài lab, ta phải smuggle một request đến Back-end sao cho request tiếp theo truy cập vào thư mục gốc (`/`) lại nhận được phản hồi `404 Not Found`.

![image.png](/assets/img/20260510-http-request-smuggling/image%207.png)

![image.png](/assets/img/20260510-http-request-smuggling/image%208.png)

**Cách kỹ thuật Differential Response hoạt động:**

1. Do Front-end không hỗ trợ chunked, nó chỉ nhìn vào `Content-Length: 34` và đẩy toàn bộ gói tin này về Back-end.
2. Khi đến Back-end, máy chủ này đọc theo `Transfer-Encoding`. Nó thấy ngay chunk `0` ở đầu Body và lập tức ngừng đọc, coi như request thứ nhất đã kết thúc.
3. Trọng tâm của kỹ thuật nằm ở phần bị bỏ lại: `GET /404 HTTP/1.1`. Đoạn mã này bị treo trong hệ thống.
4. Ngay sau đó, mở trình duyệt và truy cập vào trang chủ hệ thống (bình thường sẽ gửi đi một request như `GET / HTTP/1.1`).
5. Request hợp lệ này khi đi vào Back-end sẽ bị nối đuôi vào ngay sau dòng `hihi: haha` đang treo sẵn.
6. Kết quả là Back-end hiểu lầm rằng bạn đang muốn truy cập vào endpoint `/404` thay vì trang chủ `/`. Nó trả về kết quả `"Not Found"`. Phản hồi bị sai lệch (differential) này xác nhận chắc chắn có lỗ hổng CL.TE.

![image.png](/assets/img/20260510-http-request-smuggling/image%209.png)

#### **Write-up Lab: HTTP request smuggling, confirming a TE.CL vulnerability via differential responses**

**Mô tả đề bài:** Trong kịch bản này, máy chủ Back-end không hỗ trợ chunked encoding. Mục tiêu vẫn là buôn lậu request để request tiếp theo vào thư mục gốc (`/`) bị kích hoạt phản hồi `404 Not Found`.

![image.png](/assets/img/20260510-http-request-smuggling/image%2010.png)

![image.png](/assets/img/20260510-http-request-smuggling/image%2011.png)

**Cách kỹ thuật Differential Response hoạt động:**

1. Kẻ tấn công gửi gói tin trên. Lần này Front-end hỗ trợ chunked encoding nên nó xử lý bình thường: đọc kích thước khối `a0` (Hex), chuyển tiếp toàn bộ cục data chứa payload độc hại vào Back-end cho đến khi gặp khối `0` cuối cùng.
2. Back-end không hiểu chunked, nó chỉ đọc đúng 4 byte theo `Content-Length: 4` (tức là đọc ký tự `a`, 0 và `\r\n`). Sau 4 byte này, nó dừng lại và cho qua request đầu tiên.
3. Toàn bộ phần còn lại (bắt đầu từ `GET /404 HTTP/1.1...` kèm `Content-Length: 144`) bị treo lại Back-end.
4. Khi request hợp lệ tiếp theo của người dùng (muốn truy cập trang chủ `/`) đến, nó sẽ lao thẳng vào phần thân (chỗ chữ `hihi`) của cái bẫy `GET /404` đang chờ (vì ta đã thiết lập `Content-Length: 144` cho nó).
5. Back-end thực thi request lỗi này và trả về giao diện `Not Found` cho người dùng lẽ ra phải thấy trang chủ. Kỹ thuật xác nhận TE.CL thành công.

![image.png](/assets/img/20260510-http-request-smuggling/image%2012.png)

## 5. Khai thác HTTP Request Smuggling

Khi đã xác nhận được lỗ hổng tồn tại thông qua kỹ thuật Timing hoặc Differential Responses, bước tiếp theo là lợi dụng nó để thực hiện các cuộc tấn công cụ thể.

### 5.1. Bypass các cơ chế kiểm soát bảo mật của Front-end

Trong nhiều kiến trúc, máy chủ Front-end đóng vai trò như một người gác cổng, chặn các truy cập từ bên ngoài vào các endpoint nhạy cảm (ví dụ: `/admin`). Tuy nhiên, nếu Front-end bỏ lọt một smuggled request, máy chủ Back-end sẽ tin tưởng tuyệt đối và thực thi nó vì nó cho rằng request này đã được Front-end kiểm duyệt.  

Dưới đây là hai bài lab tiêu biểu chứng minh kỹ thuật này:

#### **Write-up Lab 1: Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability**

**Mô tả đề bài:** Front-end không hỗ trợ chunked encoding. Trang quản trị `/admin` bị Front-end chặn. smuggle một request đến Back-end để truy cập trang quản trị và xóa người dùng `carlos`. 

![image.png](/assets/img/20260510-http-request-smuggling/image%2013.png)

**Cơ chế khai thác:**

1.  Front-end dựa vào `Content-Length: 139`, cho phép toàn bộ payload đi qua vì nó không thấy endpoint `/admin` trên dòng start-line.

2.  Back-end đọc theo `Transfer-Encoding`, gặp chunk `0` liền kết thúc request đầu tiên.

3.  Đoạn `GET /admin/delete?username=carlos HTTP/1.1` bị giữ lại. Chú ý header `Host: localhost` được sử dụng để đánh lừa Back-end rằng truy cập này xuất phát từ nội bộ hệ thống.

4.  Tham số `x=` ở cuối cùng kết hợp với `Content-Length: 10` có tác dụng hứng request hợp lệ tiếp theo của người dùng (biến toàn bộ request đó thành giá trị của biến `x`), đảm bảo request không bị lỗi cú pháp khi bị nối vào. Kết quả là user `carlos` bị xóa.

![image.png](/assets/img/20260510-http-request-smuggling/image%2014.png)

![image.png](/assets/img/20260510-http-request-smuggling/image%2015.png)

#### **Write-up Lab 2: Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability**

**Mô tả đề bài:**  Lần này, Back-end không hỗ trợ chunked encoding. Tương tự, trang `/admin` bị chặn và mục tiêu là xóa user `carlos`.  

![image.png](/assets/img/20260510-http-request-smuggling/image%2016.png)

**Cơ chế khai thác:**

1. Front-end hỗ trợ chunked nên đọc kích thước khối `88` (Hex), chuyển tiếp trọn vẹn toàn bộ đoạn dữ liệu độc hại.  

2. Back-end mù chunked, chỉ nhìn vào `Content-Length: 4`. Nó đọc đúng 4 bytes (`88\r\n`) và kết thúc request thứ nhất.  

3. Đoạn mã `GET /admin/delete?username=carlos HTTP/1.1` với `Host: localhost` bị treo lại.

4. Chữ `hihi` đóng vai trò là vùng đệm, chờ đợi request tiếp theo của nạn nhân nối vào để Back-end thực thi lệnh xóa.

![image.png](/assets/img/20260510-http-request-smuggling/image%2017.png)

![image.png](/assets/img/20260510-http-request-smuggling/image%2018.png)

### 5.2. Các hướng khai thác nâng cao khác

1. **Tiết lộ cơ chế ghi đè Request của Front-end (Revealing front-end request rewriting):** Front-end thường chèn thêm các header riêng (ví dụ: `X-Forwarded-For`) trước khi gửi cho Back-end. Smuggling có thể giúp ta tiết lộ các header ẩn này.  
2. **Đánh cắp Request của người dùng khác (Capturing other users' requests):** Bằng cách gửi một request lậu có chức năng phản hồi lại nội dung do người dùng nhập vào (chẳng hạn chức năng lưu comment), ta có thể hứng toàn bộ request của nạn nhân (bao gồm cả Cookie/Session) và ghi vào cơ sở dữ liệu.
3. **Vượt qua xác thực máy khách (Bypassing client authentication):** Dùng request lậu để mạo danh trạng thái đã xác thực.  
4. **Sử dụng Request Smuggling để khai thác Reflected XSS:** Biến một lỗi XSS yêu cầu tương tác người dùng thành một lỗi XSS có thể nhắm vào bất kỳ ai đang truy cập trang web mà không cần họ click vào link. 
5. **Chuyển hướng mở và Đầu độc bộ nhớ đệm (Open Redirect, Web Cache Poisoning & Deception):** Kết hợp Smuggling với Open Redirect để đầu độc Web Cache, khiến toàn bộ người dùng sau đó bị điều hướng đến máy chủ độc hại, hoặc để đánh lừa bộ nhớ đệm nhằm rò rỉ thông tin cá nhân.

## 6. Lỗ hổng HTTP Request Smuggling nâng cao

Trong các hệ thống hiện đại, máy chủ Front-end thường giao tiếp với người dùng bằng HTTP/2 để tối ưu hóa hiệu suất, nhưng lại hạ cấp (downgrade) các request này xuống HTTP/1.1 khi chuyển tiếp đến Back-end.

Điểm chết người nằm ở đây: HTTP/2 sử dụng cơ chế chia khung nhị phân (binary framing) để xác định độ dài gói tin, nên nó không thực sự cần đến `Content-Length` hay `Transfer-Encoding`. Tuy nhiên, khi Front-end dịch sang HTTP/1.1, nó bắt buộc phải chèn thêm các header này. Nếu quá trình phiên dịch không chặt chẽ (ví dụ: cho phép chèn header tùy ý hoặc giữ nguyên các header mâu thuẫn), kẻ tấn công có thể tạo ra các lỗ hổng như **H2.CL** hoặc **H2.TE**.

#### Write-up Lab: H2.CL request smuggling

**Mô tả đề bài:** Máy chủ Front-end hạ cấp request HTTP/2 xuống HTTP/1.1 ngay cả khi độ dài của gói tin không rõ ràng. Nạn nhân (victim) có thói quen truy cập vào trang chủ cứ mỗi 10 giây một lần. Thực hiện tấn công request smuggling để lừa trình duyệt của nạn nhân tải và thực thi một tệp JavaScript độc hại từ máy chủ của kẻ tấn công (Exploit Server), từ đó hiển thị popup `alert(document.cookie)`. 

![image.png](/assets/img/20260510-http-request-smuggling/image%2019.png)

Ta thực hiện chèn payload thử nghiệm vào. Lúc này có thể thấy backend thực hiện chuyển hướng đến `ex.com/resources`. Qua đó ta sẽ thiết lập Exploit Server theo đường dẫn này.

![image.png](/assets/img/20260510-http-request-smuggling/image%2020.png)

![image.png](/assets/img/20260510-http-request-smuggling/image%2021.png)

Đầu tiên, ta cấu hình máy chủ của mình để khi có người truy cập vào đường dẫn `/resources`, nó sẽ trả về mã JavaScript độc hại:

- **Head:** `HTTP/1.1 200 OK` và `Content-Type: application/javascript; charset=utf-8`
- **Body:** `alert(document.cookie)`

![image.png](/assets/img/20260510-http-request-smuggling/image%2022.png)

![image.png](/assets/img/20260510-http-request-smuggling/image%2023.png)

**Cơ chế khai thác (Flow của cuộc tấn công):**

1. **Lợi dụng HTTP/2:** Ta gửi một request POST qua HTTP/2. Mặc dù ta khai báo `Content-Length: 0`, cấu trúc binary frame của HTTP/2 vẫn gói phần body (chứa đoạn `GET /resources...`) và gửi đi bình thường đến Front-end.
2. **Quá trình hạ cấp (Downgrade) tai hại:** Front-end nhận request, dịch nó sang HTTP/1.1 và chuyển cho Back-end. Kẻ hở là nó giữ nguyên header `Content-Length: 0` mà ta đã chèn vào.
3. **Back-end sập bẫy (CL):** Back-end (HTTP/1.1) đọc thấy `Content-Length: 0` nên lập tức ngừng đọc phần body. Nó coi như request POST đầu tiên đã xong.
4. **Smuggling thành công:** Phần body chứa đoạn `GET /resources HTTP/1.1` trỏ thẳng tới máy chủ `exploit-server.net` của ta bị kẹt lại trong hệ thống mạng của Back-end.
5. Khi nạn nhân truy cập trang chủ (định kỳ 10 giây/lần), request hợp lệ của họ nhằm lấy các file tĩnh (resources) của trang web sẽ bị nối đuôi vào ngay sau `hihi=hah`.
6. Hậu quả là Back-end trả về phản hồi từ máy chủ độc hại của ta thay vì máy chủ gốc, trình duyệt nạn nhân tải file JS lạ và kích hoạt `alert(document.cookie)`. Lab Solved!

![image.png](/assets/img/20260510-http-request-smuggling/image%2024.png)

### Các bề mặt tấn công nâng cao khác

Bên cạnh H2.CL/H2.TE, HTTP Request Smuggling còn tiến hóa thành nhiều nhánh phức tạp khác mà các pentester cần lưu tâm (dành cho phần tham khảo mở rộng):

- **Đầu độc hàng đợi phản hồi (Response queue poisoning):** Đánh cắp hoặc làm sai lệch phản hồi dành cho người dùng khác.
- **Request smuggling via CRLF injection:** Chèn các ký tự ngắt dòng để tự tạo các header nguy hiểm trong quá trình Front-end ghi đè request.
- **HTTP/2 request splitting:** Tương tự smuggling nhưng nhắm trực tiếp vào cơ chế chia tách frame của HTTP/2.
- **Đường hầm HTTP (HTTP request tunnelling):** Buôn lậu request qua một luồng kết nối liên tục để bypass các bộ lọc.
- **Browser-powered request smuggling:** Lợi dụng chính trình duyệt để thực hiện desync.
- **CL.0 request smuggling:** Lỗ hổng xảy ra khi Back-end phớt lờ hoàn toàn body của một số endpoint cụ thể và tự mặc định `Content-Length` là 0.
- **Client-side desync attacks & Pause-based desync attacks:** Các dạng tấn công bất đồng bộ diễn ra ngay tại phía client hoặc lợi dụng độ trễ trong việc đọc gói tin.

## 7. Tổng kết & Biện pháp phòng chống (Mitigation)

### 7.1. Tổng kết

HTTP Request Smuggling không phải là một lỗ hổng nằm ở mã nguồn ứng dụng (như SQL Injection hay XSS), mà nó nằm ở **lỗ hổng kiến trúc** – sự bất đồng bộ trong cách các máy chủ (Front-end và Back-end) diễn giải cùng một giao thức.

Chính vì đặc thù này, Request Smuggling cực kỳ nguy hiểm. Một khi kẻ tấn công đã kiểm soát được đường ống (pipeline) và lách qua được Front-end, toàn bộ các lớp giáp bảo vệ như WAF, cơ chế phân quyền (Access Control), hay kiểm tra tính hợp lệ của dữ liệu đều trở nên vô nghĩa. Từ việc đánh cắp session, chiếm quyền admin cho đến đầu độc toàn bộ hệ thống Cache, hậu quả mà nó để lại là không thể lường trước.

### 7.2. Biện pháp phòng chống hiệu quả

Để giảm thiểu rủi ro từ HTTP Request Smuggling, các kỹ sư hệ thống và chuyên gia bảo mật cần áp dụng các biện pháp sau:

**1. Sử dụng HTTP/2 End-to-End:** Căn nguyên của nhiều lỗi Smuggling là do quá trình hạ cấp (downgrade) từ HTTP/2 xuống HTTP/1.1 hoặc do sự nhập nhằng giữa `Content-Length` và `Transfer-Encoding`. Việc sử dụng HTTP/2 cho toàn bộ vòng đời của request (từ Client -> Front-end -> Back-end) giúp giảm mạnh rủi ro CL.TE/TE.CL truyền thống, vì HTTP/2 sử dụng cơ chế khung nhị phân (binary framing) được xác định độ dài rõ ràng. Tuy nhiên, vẫn cần kiểm tra các biến thể desync khác như HTTP/2 request splitting hoặc client-side desync tùy cách triển khai.

**2. Chuẩn hóa Request tại Front-end (Request Normalization):**

Nếu bắt buộc phải dùng HTTP/1.1 ở Back-end, máy chủ Front-end phải được cấu hình để chuẩn hóa các request mập mờ một cách cực kỳ khắt khe:

- Từ chối (Drop) ngay lập tức các request chứa cả hai header `Content-Length` và `Transfer-Encoding`.
- Từ chối các request chứa nhiều header `Transfer-Encoding` hoặc header TE bị làm méo mó (obfuscated).
- Front-end phải định tuyến lại gói tin sao cho Back-end nhận được một cấu trúc duy nhất và rõ ràng.

**3. Vô hiệu hóa việc sử dụng lại kết nối (Disable Connection Reuse):**

Lỗ hổng chỉ xảy ra khi nhiều request chia sẻ chung một luồng kết nối TCP (TCP connection). Nếu cấu hình máy chủ đóng kết nối ngay sau khi xử lý xong một request (tắt Keep-Alive giữa Front-end và Back-end), kẻ tấn công sẽ không thể treo mã độc để bẫy request tiếp theo. Tuy nhiên, cách này có thể làm giảm hiệu suất hệ thống đáng kể.

**4. Cấu hình Back-end từ chối các kết nối dị thường:**

Back-end không nên tin tưởng tuyệt đối vào Front-end. Nếu Back-end nhận thấy một request có dấu hiệu bất thường (như thừa thãi dữ liệu sau khi đã đọc hết Content-Length), nó cần chủ động ngắt kết nối đó ngay lập tức thay vì để dữ liệu tồn đọng trong pipeline.
