---
title: Web Cache Poisoning
date: 2026-05-03 10:00:00 +0700
categories: [Web Security, PortSwigger]
tags: [web-cache-poisoning, cache, portswigger, writeup]
---

## 1. Web Cache Poisoning là gì?

Web Cache Poisoning là kỹ thuật lợi dụng sự khác biệt giữa cách cache server tạo cache key và cách ứng dụng backend xử lý request. Nếu một phần dữ liệu trong request ảnh hưởng đến response nhưng không được đưa vào cache key, attacker có thể chèn payload vào phần dữ liệu đó, khiến cache lưu lại response độc hại và phân phát nó cho nhiều người dùng khác.

Trong thực tế, cache thường chỉ dùng một số thành phần chính để định danh response, ví dụ:

- Host
- Path
- Query string hoặc một phần query string
- Một số header quan trọng như `Accept-Encoding`

Những thành phần được đưa vào cache key gọi là **keyed input**. Ngược lại, các header, cookie hoặc parameter không được cache xét đến nhưng vẫn được backend sử dụng gọi là **unkeyed input**. Đây chính là nơi Web Cache Poisoning thường xuất hiện.

## 2. Điều kiện để khai thác

Một lỗi Web Cache Poisoning thường cần đủ ba điều kiện:

- Response phải cache được.
- Request có một input không nằm trong cache key.
- Input đó phải tác động được đến response theo cách có thể khai thác, ví dụ chèn script, đổi host của file JavaScript, hoặc ép redirect.

Khi kiểm thử, mình thường tìm các dấu hiệu như `X-Cache: hit`, `X-Cache: miss`, `Age`, `Cache-Control`, hoặc các response có nội dung thay đổi sau khi thêm header/query/cookie lạ.

## 3. Exploiting Cache Design Flaws

Cache design flaws xảy ra khi hệ thống cache được thiết kế bỏ qua một thành phần quan trọng của request, trong khi backend lại tin và sử dụng thành phần đó để dựng response.

### Lab 1: Web cache poisoning with an unkeyed header

Ở lab này, mục tiêu là tìm một header không nằm trong cache key nhưng lại được backend phản ánh vào response. Khi header đó điều khiển được URL của một resource như JavaScript, ta có thể thay URL sang Exploit Server và khiến nạn nhân tải script độc hại.

![image.png](/assets/img/20260503-web-cache-poisoning/image.png)

Đầu tiên, bắt request bằng Burp Suite và gửi sang Repeater. Mình thử thêm các header phổ biến dùng trong proxy chain như `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Scheme` để quan sát response.

Ví dụ request test:

```http
GET / HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: exploit-server.net
```

![image.png](/assets/img/20260503-web-cache-poisoning/image%201.png)

Khi thêm header phù hợp, response bắt đầu thay đổi nhưng cache key vẫn không thay đổi theo header này. Đây là dấu hiệu input đang là unkeyed header.

![image.png](/assets/img/20260503-web-cache-poisoning/image%202.png)

Tiếp theo, thay giá trị header thành domain của Exploit Server. Nếu response sinh ra URL resource dựa trên header này, trình duyệt của nạn nhân sẽ tải tài nguyên từ server do attacker kiểm soát.

![image.png](/assets/img/20260503-web-cache-poisoning/image%203.png)

Trên Exploit Server, tạo file JavaScript trả về payload đơn giản như `alert(document.cookie)`. Sau đó gửi request poison nhiều lần cho đến khi thấy cache hit.

```http
HTTP/1.1 200 OK
Content-Type: application/javascript; charset=utf-8

alert(document.cookie)
```

![image.png](/assets/img/20260503-web-cache-poisoning/image%204.png)

Khi cache đã lưu response độc hại, người dùng khác truy cập cùng URL sẽ nhận response bị poison và tải script từ Exploit Server.

![image.png](/assets/img/20260503-web-cache-poisoning/image%205.png)

### Lab 2: Web cache poisoning with an unkeyed cookie

Không chỉ header, cookie cũng có thể là unkeyed input. Nếu backend dùng giá trị cookie để dựng response nhưng cache không đưa cookie đó vào cache key, attacker có thể đầu độc cache bằng một cookie tự tạo.

![image.png](/assets/img/20260503-web-cache-poisoning/image%206.png)

Trong request ban đầu, quan sát các cookie có sẵn và thử thay đổi từng giá trị để xem response có bị ảnh hưởng không.

Ví dụ, nếu response sử dụng giá trị cookie để dựng URL hoặc nội dung HTML:

```http
GET / HTTP/1.1
Host: vulnerable-website.com
Cookie: fehost=exploit-server.net
```

![image.png](/assets/img/20260503-web-cache-poisoning/image%207.png)

Khi một cookie làm thay đổi URL hoặc nội dung trong response, gửi lại request nhiều lần để xác định response đó có được cache hay không.

![image.png](/assets/img/20260503-web-cache-poisoning/image%208.png)

Sau khi xác nhận cookie là unkeyed, thay giá trị của nó thành payload hoặc domain của Exploit Server, tùy vị trí phản ánh trong response.

![image.png](/assets/img/20260503-web-cache-poisoning/image%209.png)

Nếu cache lưu response độc hại, những request sau không cần gửi cookie vẫn có thể nhận nội dung đã bị poison vì cache key không phân biệt giá trị cookie.

Dấu hiệu cần kiểm tra là response thay đổi theo cookie, nhưng trạng thái cache vẫn chuyển từ `miss` sang `hit` cho cùng một URL.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2010.png)

Kết quả là nạn nhân truy cập URL bình thường nhưng nhận response đã bị attacker kiểm soát.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2011.png)

### Lab 3: Web cache poisoning with multiple headers

Một số trường hợp không thể poison cache chỉ bằng một header đơn lẻ. Attacker cần kết hợp nhiều header để tạo ra response có thể khai thác, ví dụ một header kích hoạt redirect và một header khác điều khiển domain trong `Location`.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2012.png)

Đầu tiên, thử từng header proxy phổ biến để tìm header nào tác động đến response.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2013.png)

Sau đó kết hợp các header lại với nhau. Khi response bắt đầu redirect hoặc sinh URL khác thường, cần kiểm tra phần nào của request đang được backend tin tưởng.

Một payload thường gặp là kết hợp header điều khiển scheme với header điều khiển host:

```http
GET / HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Scheme: nothttps
X-Forwarded-Host: exploit-server.net
```

![image.png](/assets/img/20260503-web-cache-poisoning/image%2014.png)

Trong kịch bản này, một header có thể khiến backend nghĩ request đang dùng scheme khác, còn header còn lại điều khiển host đích.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2015.png)

Khi đã tạo được response redirect về Exploit Server, tiếp tục kiểm tra trạng thái cache hit/miss để đảm bảo response này có thể bị lưu lại.

Nếu response trả về `Location: https://exploit-server.net/...` và sau đó cùng URL nhận `X-Cache: hit`, nghĩa là redirect độc hại đã được cache lưu lại.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2016.png)

Gửi request poison đến đúng URL mục tiêu và đợi cache lưu response độc hại.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2017.png)

Khi nạn nhân truy cập URL đã bị poison, cache trả về response redirect hoặc resource độc hại mà không cần backend xử lý lại.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2018.png)

Lab được solve khi payload trên Exploit Server được thực thi.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2019.png)

## 4. Exploiting Cache Implementation Flaws

Cache implementation flaws xảy ra khi cache server và backend parse request theo hai cách khác nhau. Điểm nguy hiểm nằm ở chỗ cache có thể bỏ qua một query string hoặc parameter, trong khi backend vẫn sử dụng nó để dựng response.

### Lab 4: Web cache poisoning via an unkeyed query string

Ở lab này, toàn bộ query string không được đưa vào cache key. Backend vẫn phản ánh hoặc sử dụng query string trong response, nên attacker có thể chèn payload qua URL.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2020.png)

Thử thêm query string ngẫu nhiên vào URL và quan sát response. Nếu response thay đổi nhưng cache vẫn trả về cùng một key cho path, đây là dấu hiệu query string bị unkeyed.

Ví dụ:

```http
GET /?evil='><script>alert(1)</script> HTTP/1.1
Host: vulnerable-website.com
```

![image.png](/assets/img/20260503-web-cache-poisoning/image%2021.png)

Tiếp theo, chèn payload vào query string và kiểm tra xem payload có xuất hiện trong response hay không.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2022.png)

Sau khi xác nhận payload được phản ánh, gửi request cho đến khi cache lưu bản response độc hại.

Cần so sánh hai request: một request có query string chứa payload và một request chỉ truy cập path gốc. Nếu request path gốc vẫn nhận response chứa payload sau khi cache hit, query string đang bị loại khỏi cache key.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2023.png)

Khi người dùng truy cập path gốc không kèm query string, cache vẫn có thể trả về response đã bị poison vì query string không nằm trong cache key.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2024.png)

### Lab 5: Web cache poisoning via an unkeyed query parameter

Khác với lab trước, lần này cache không bỏ qua toàn bộ query string mà chỉ bỏ qua một số parameter nhất định. Những parameter này thường dùng cho tracking như `utm_source`, `utm_content`, `cb`, hoặc các tham số analytics khác.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2025.png)

Sử dụng Burp Param Miner hoặc thử thủ công để tìm parameter không nằm trong cache key nhưng vẫn được backend xử lý.

Ví dụ các parameter hay bị cache bỏ qua:

```http
GET /?utm_content=payload HTTP/1.1
Host: vulnerable-website.com
```

```http
GET /?cb=payload HTTP/1.1
Host: vulnerable-website.com
```

![image.png](/assets/img/20260503-web-cache-poisoning/image%2026.png)

Khi tìm được parameter phù hợp, chèn payload vào giá trị của parameter đó và kiểm tra response.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2027.png)

Nếu payload được phản ánh trong response, gửi request nhiều lần cho tới khi cache hit.

Điểm cần chứng minh là thay đổi giá trị parameter làm backend đổi response, nhưng cache vẫn coi URL này tương đương với URL không có parameter đó hoặc với parameter khác giá trị.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2028.png)

Do parameter này không nằm trong cache key, người dùng truy cập URL bình thường vẫn có thể nhận response chứa payload.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2029.png)

### Lab 6: Parameter cloaking

Parameter cloaking lợi dụng sự khác biệt trong cách cache và backend parse query string. Không phải cứ thêm `;` là khai thác được; điều kiện quan trọng là cache và backend phải hiểu delimiter hoặc parameter theo hai cách khác nhau. Ví dụ, cache có thể coi `;` là một phần của giá trị parameter, trong khi backend lại coi nó là dấu phân tách parameter mới.

![image.png](/assets/img/20260503-web-cache-poisoning/image%2030.png)

Ý tưởng là tạo một URL mà cache nhìn thấy như một request hợp lệ đã được key theo parameter an toàn, nhưng backend lại parse ra thêm một parameter độc hại. Nếu parameter độc hại điều khiển callback, script hoặc nội dung response, attacker có thể poison cache mà không làm cache key thay đổi như mong đợi.

Ví dụ minh họa:

```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1) HTTP/1.1
Host: vulnerable-website.com
```

Trong ví dụ này, cache có thể key theo `callback=setCountryCookie`, còn backend lại parse thêm `callback=alert(1)` ở phía sau dấu `;`. Khi đó, response do backend tạo ra có thể chứa callback độc hại, nhưng cache vẫn lưu nó dưới key tưởng như an toàn.

Ví dụ flow khai thác:

1. Xác định một endpoint cache được và có parameter ảnh hưởng đến response.
2. Thử các ký tự phân tách như `;`, `%3b`, `%26` để xem cache và backend parse khác nhau không.
3. Đặt payload vào parameter bị cloaking.
4. Gửi request poison cho đến khi cache hit.
5. Truy cập URL bình thường để kiểm tra payload đã được cache phục vụ cho người dùng khác.

## 5. Cách phòng chống Web Cache Poisoning

Để giảm rủi ro Web Cache Poisoning, cần xử lý cả phía cache server lẫn backend application:

- Chỉ cache các response thật sự an toàn và cần thiết.
- Đưa mọi input ảnh hưởng đến response vào cache key, đặc biệt là header, cookie và query parameter đặc biệt.
- Không tin tưởng các header như `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host` nếu chúng không được kiểm soát bởi proxy tin cậy.
- Không phản ánh trực tiếp user input vào HTML, JavaScript hoặc URL resource.
- Với response có dữ liệu động hoặc phụ thuộc user, dùng `Cache-Control: private` hoặc `Cache-Control: no-store`.
- Chuẩn hóa request tại reverse proxy trước khi chuyển vào backend.
- Kiểm tra định kỳ bằng các công cụ như Burp Param Miner để phát hiện unkeyed input.

## 6. Tổng kết

Web Cache Poisoning nguy hiểm vì attacker chỉ cần gửi một request độc hại nhưng có thể khiến rất nhiều người dùng nhận cùng response bị đầu độc. Gốc rễ của vấn đề thường không nằm ở một dòng code đơn lẻ, mà nằm ở sự bất đồng giữa cache layer và backend layer.

Khi kiểm thử, điều quan trọng nhất là luôn tự hỏi: input nào đang ảnh hưởng đến response, và input đó có nằm trong cache key hay không. Nếu câu trả lời là "có ảnh hưởng nhưng không được key", đó chính là điểm bắt đầu của Web Cache Poisoning.
