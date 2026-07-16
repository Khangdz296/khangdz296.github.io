---
title: Access Control Vulnerabilities
date: 2026-07-14 10:00:00 +0700
categories: [Web Security, PortSwigger]
tags: [access control, portswigger, writeup]
---

## 1. What is access control?

Access control là cơ chế quyết định một user đã được xác thực có được phép thực hiện một hành động hoặc truy cập một tài nguyên nào đó hay không. Nếu authentication trả lời câu hỏi "bạn là ai?", thì access control trả lời câu hỏi "bạn được phép làm gì?".

Trong ứng dụng web, access control thường xuất hiện ở nhiều lớp khác nhau:

- Truy cập endpoint hoặc route, ví dụ `/admin`, `/api/users/1`.
- Truy cập object hoặc bản ghi dữ liệu, ví dụ hóa đơn, profile, file, API key.
- Thực hiện hành động nhạy cảm, ví dụ xóa user, đổi role, cập nhật email, reset password.
- Truy cập chức năng theo trạng thái hiện tại của ứng dụng, ví dụ chỉ được thanh toán sau khi đã chọn sản phẩm.

Một lỗi phổ biến là ứng dụng chỉ ẩn chức năng trên giao diện nhưng không kiểm tra quyền ở phía server. Vì request HTTP có thể được sửa trực tiếp bằng Burp Suite hoặc các công cụ tương tự, mọi quyết định phân quyền quan trọng phải được thực thi ở backend.

### 1.1 Vertical access controls

Vertical access control là kiểm soát quyền giữa các cấp đặc quyền khác nhau. Ví dụ, admin có thể truy cập trang quản trị, xóa user hoặc thay đổi role; user bình thường thì không được phép thực hiện các hành động này.

Khi vertical access control bị lỗi, attacker có thể leo thang đặc quyền từ user thường lên admin hoặc truy cập các chức năng đáng lẽ chỉ dành cho role cao hơn. Một vài nguyên nhân thường gặp gồm:

- Endpoint quản trị không được bảo vệ, chỉ bị ẩn khỏi giao diện.
- Ứng dụng tin vào tham số phía client như cookie `Admin=true`, `roleid=2`.
- Backend kiểm tra quyền không đồng nhất giữa các HTTP method.
- Frontend, proxy hoặc framework rewrite URL khác với cách backend xử lý request.

### 1.2 Horizontal access controls

Horizontal access control là kiểm soát quyền giữa các user có cùng cấp đặc quyền. Ví dụ, user `wiener` và `carlos` đều là user bình thường, nhưng `wiener` chỉ được xem dữ liệu của chính mình, không được xem API key, hóa đơn hoặc file riêng của `carlos`.

Lỗi horizontal access control thường xảy ra khi ứng dụng lấy object dựa trên tham số do client cung cấp nhưng không kiểm tra object đó có thuộc về user hiện tại hay không. Dạng lỗi này hay gặp trong các URL như:

```text
/my-account?id=wiener
/api/orders/123
/download?file=1.txt
```

Nếu attacker chỉ cần đổi `id`, `username`, `file`, `orderId` hoặc GUID để đọc dữ liệu của người khác, đó là dấu hiệu rõ ràng của broken access control.

### 1.3 Context-dependent access controls

Context-dependent access control là kiểm soát quyền dựa trên trạng thái, ngữ cảnh hoặc luồng xử lý của ứng dụng. Không phải lúc nào user cũng được phép thực hiện một hành động chỉ vì họ có role hợp lệ; hành động đó còn phải đúng thời điểm và đúng quy trình.

Ví dụ:

- User chỉ được thanh toán sau khi giỏ hàng đã được xác nhận.
- Chỉ được đổi email sau khi đã nhập lại mật khẩu hoặc xác nhận OTP.
- Chỉ được hoàn tất nâng quyền sau khi đã đi qua bước xác nhận.
- Chỉ được truy cập chức năng nội bộ khi request xuất phát từ một workflow hợp lệ.

Khi kiểm soát theo ngữ cảnh bị thiếu, attacker có thể bỏ qua một bước trong quy trình, gọi thẳng endpoint cuối cùng hoặc lặp lại request cũ để thực hiện hành động không hợp lệ.

## 2. Examples of broken access controls

Broken access control có thể xuất hiện dưới nhiều hình thức khác nhau, nhưng điểm chung là server cho phép user làm điều mà chính sách phân quyền không cho phép. Khi kiểm thử, mình thường tập trung vào việc thay đổi đường dẫn, parameter, cookie, method, header và thứ tự các bước trong workflow để xem backend có kiểm tra quyền thật sự hay không.

### 2.1 Vertical privilege escalation

Vertical privilege escalation xảy ra khi user có quyền thấp truy cập được chức năng của user có quyền cao hơn. Trong web app, mục tiêu thường là admin panel, chức năng đổi role, xóa user hoặc đọc dữ liệu quản trị.

#### Unprotected functionality

![lab](/assets/img/20260714-access-control/image1.png)

Bài lab này mô tả trang admin không được bảo vệ đúng cách, truy cập và xóa người dùng `Carlos`

Đầu tiên mình thử các đường dẫn admin phổ biến như:

```text
/admin
/Admin
/administrator
```

Từ nội dung mà mình đã đọc ở Portswigger thì mình biết được đường dẫn admin có thể được leak ra ở nơi khác. Do đó mình thử đường dẫn `/robots.txt`. Truy cập thành công và mình thu được đường dẫn admin:

![lab](/assets/img/20260714-access-control/image2.png)

Truy cập vào `/administrator-panel` và thực hiện xóa user `carlos` để hoàn thành bài lab.

![lab](/assets/img/20260714-access-control/image3.png)

#### Unprotected admin functionality with unpredictable URL

![lab](/assets/img/20260714-access-control/image4.png)

Bài lab này mô tả trang admin vẫn không được bảo vệ đúng cách. Và đường dẫn truy cập thì khó có thể dự đoán nhưng đường dẫn này lại được leak ở một nơi nào đó trong ứng dụng.

Với gợi ý này thì mình tiến hành đọc source của trang web để tìm xem đường dẫn admin có bị lộ ra ở đây không.

![lab](/assets/img/20260714-access-control/image5.png)

Mình thành công tìm được đường dẫn admin trong đoạn script check user có phải admin hay không.

Truy cập admin panel bằng đường dẫn vừa tìm được `/admin-xmjqe4` và xóa user `carlos` để hoàn thành bài lab.

![lab](/assets/img/20260714-access-control/image6.png)

#### Parameter-based access control methods

Một số ứng dụng lưu trạng thái phân quyền trong parameter, cookie hoặc field phía client. Nếu backend tin trực tiếp vào các giá trị này, attacker có thể sửa request để tự cấp quyền cho mình.

##### Lab: User role controlled by request parameter

![lab](/assets/img/20260714-access-control/image7.png)

Bài lab này mô tả trang web có trang admin ở đường dẫn `/admin`, nhưng được xác thực bởi cookie có thể làm giả.

Từ gợi ý của bài lab mình thực hiện đăng nhập với credential được cho sẵn `wiener:peter` để thực hiện fake cookie.

![lab](/assets/img/20260714-access-control/image8.png)

Ta dễ dàng nhìn thấy được có một trường cookie là `Admin:false`. Việc cần làm bây giờ là chỉ cần chỉnh value thành `true` và load lại trang.

![lab](/assets/img/20260714-access-control/image9.png)

Lúc này tab admin hiện ra truy cập vào và xóa user `carlos` để hoàn thành bài lab.

![lab](/assets/img/20260714-access-control/image10.png)

##### Lab: User role can be modified in user profile

![lab](/assets/img/20260714-access-control/image11.png)

Bài lab này cũng tương tự như bài trước có trang admin tại `/admin`. Nhưng ở bài này khác một chút là chỉ có thể truy cập với user có `roleid = 2`.

Ban đầu thì mình nghĩ nó chỉ là thực hiện chèn tham số `roleid` vào các đường dẫn như `/my-account` hoặc `/login`. Nhưng sau nhiều lần thử thì đều không được, lúc này thì mình mới thử thực hiện chức năng update email và phát hiện trong respone có trả về trường `roleid`

![lab](/assets/img/20260714-access-control/image12.png)

Mình thử chèn thêm trường `roleid:2` đi kèm với `email` xem thử nó có thể ghi đè được `roleid` trong respone không.

![lab 4](/assets/img/20260714-access-control/image13.png)

Kết quả `roleid` bị ghi đè và với account là `wiener` thì mình có thể truy cập vào admin panel.

![lab 4](/assets/img/20260714-access-control/image14.png)

Xóa user `carlos` để hoàn thành bài lab.

#### Broken access control resulting from platform misconfiguration

Access control cũng có thể bị bypass do cấu hình sai ở proxy, frontend server hoặc framework. Ví dụ, một lớp chặn request dựa trên URL gốc, nhưng backend lại hỗ trợ các header rewrite như `X-Original-URL` hoặc xử lý method khác nhau giữa `GET` và `POST`.

##### Lab: URL-based access control can be circumvented

![lab 4](/assets/img/20260714-access-control/image15.png)

Bài lab này mô tả một trang web không có xác thực ở trang admin với đường dẫn `/admin`. Nhưng mà front-end thì có cấu hình để block truy cập từ bên ngoài vào đường dẫn này. Tuy nhiên phía backend thì lại build trên framework có hỗ trợ header X-Original-URL.

![lab 4](/assets/img/20260714-access-control/image16.png)

Bài này khá đơn giản chỉ cần dùng BurpSuite bắt một request và thêm header `X-Original-URL: /admin` vào trong request truy cập vào `/`. Lúc này thì frontend tưởng rằng mình chỉ truy cập vào trang chủ chứ không hề biết có sự can thiệp của header `X-Original-URL`. Nhờ header này khi đến backend request sẽ truy cập vào admin panel.

Thực hiện xóa user `carlos` để hoàn thành bài lab.

![lab 4](/assets/img/20260714-access-control/image17.png)

##### Lab: Method-based access control can be circumvented

![lab 4](/assets/img/20260714-access-control/image18.png)

Bài này mô tả trang web này kiểm soát truy cập dựa vào HTTP method. Để hoàn thành bài lab thì cần sử dụng credential được cho sẵn và khai thác lỗi kiểm soát truy cập này để nâng quyền account này lên admin.

Đề bài có đưa thêm credential của admin là `administrator:admin` để làm quen với admin panel.

Khi vào admin panel với credential admin thì mình đã xem được request upgrade một user lên quyền cao hơn.

![lab 4](/assets/img/20260714-access-control/image19.png)

Bây giờ mình cần thực hiện nâng quyền user hiện tại là `wiener` lên. Với request upgrade đã có trước đó mình thử gửi request với `username:wiener` thì nhận respone với status `401`.

Lúc này mình dựa vào mô tả đã cho. Với POST method bị từ chối, mình thử chuyên thành GET method và gửi lại request tới server. Kết quả thành công upgrade được quyền của user `wiener`.

![lab 4](/assets/img/20260714-access-control/image20.png)

### 2.2 Horizontal privilege escalation

Horizontal privilege escalation xảy ra khi một user truy cập được dữ liệu hoặc chức năng thuộc về user khác có cùng cấp quyền. Đây là nhóm lỗi rất phổ biến vì nhiều ứng dụng dùng ID trên URL hoặc API request để xác định object cần truy xuất.

#### Lab: User ID controlled by request parameter

![lab 4](/assets/img/20260714-access-control/image21.png)

Bài này mô tả có lỗ hổng leo thang đặc quyền theo chiều ngang trong trang account. Hoàn thành bài lab bằng cách lấy API key của user `carlos` và submit.

![lab 4](/assets/img/20260714-access-control/image22.png)

Trang account của user `wiener` với thông tin hiển thị gồm `username` và `API key`. Mình thử đổi `id` trên url từ `wiener` thành `carlos` và kết quả là truy được vào trang account của user `carlos`.

![lab 4](/assets/img/20260714-access-control/image23.png)

Submit với API key này và hoàn thành bài lab.

#### Lab: User ID controlled by request parameter, with unpredictable user IDs

Bài này cũng tương tự với bài trên nhưng các user được xác định bởi GUID. Để giải quyết bài lab thì phải tìm được GUID của user `carlos` và lấy API key.

![lab 4](/assets/img/20260714-access-control/image24.png)

Với dạng này thì gần như không thể leo thang sang user khác bằng cách dự đoán được. Lúc này mình mới đi đọc các blog check xem có lộ GUID trong source không.

Thì mình phát hiện GUID của các user khác bị lộ khi mà thực hiện đăng bài post. Lúc này mình tìm blog của user `carlos` để lấy GUID.

![lab 4](/assets/img/20260714-access-control/image25.png)

Với GUID của user `carlos` vừa lấy được thực hiện truy cập vào trang account của user này với đường dẫn `/my-account?id=cce3fbad-e24c-4b35-9365-3c9edfde4101`. Thành công lấy được API key

![lab 4](/assets/img/20260714-access-control/image26.png)

#### Lab: User ID controlled by request parameter with data leakage in redirect

![lab 4](/assets/img/20260714-access-control/image27.png)

Bài này mô tả là dữ liệu nhạy cảm có thể được leak thông qua nội dung trong redirect response.

Ở trang account của user `wiener`, mình thử thay đổi trường id từ `wiener` thành `carlos`

![lab 4](/assets/img/20260714-access-control/image28.png)

Kết quả là bị redirect sang trang đăng nhập. Mình kiểm tìm request này trong burpsuite và kiểm tra response kết quả là có thông tin của user `carlos`.

![lab 4](/assets/img/20260714-access-control/image29.png)

Submit API key và hoàn thành bài lab.

### 2.3 Horizontal to vertical privilege escalation

Một số lỗi ban đầu chỉ là horizontal privilege escalation, nhưng nếu object bị truy cập thuộc về admin thì attacker có thể dùng dữ liệu đó để leo thang lên quyền cao hơn. Ví dụ điển hình là đọc được password, token, API key hoặc thông tin reset password của admin.

#### Lab: User ID controlled by request parameter with password disclosure

![lab 4](/assets/img/20260714-access-control/image30.png)

Bài lab này mô tả trang account có chứa password và được điền sẵn trong ô input đã được ẩn. Thực hiện truy cập vào trang account của `admin` và lấy password của `admin` sau đó xóa user `carlos`.

![lab 4](/assets/img/20260714-access-control/image31.png)

Đầu tiên mình truy cập vào trang account của user `wiener`. Và thấy được password này có thể lấy được bằng cách check source hoặc là đổi mật khẩu khác bằng chức năng `update password`.

Mình thực hiện chỉnh id từ user `wiener` sang `administrator` để leo thang đặc quyền ngang truy cập vào user admin.

![lab 4](/assets/img/20260714-access-control/image32.png)

Lấy được password `admin`. Mình đăng nhập vào admin panel và xóa user carlos để hoàn thành bài lab.

### 2.4 Insecure direct object references

Insecure Direct Object Reference, thường gọi là IDOR, là một dạng broken access control trong đó ứng dụng expose trực tiếp định danh của object và không kiểm tra quyền sở hữu trước khi trả dữ liệu. Object có thể là file, record database, hóa đơn, transcript, ảnh riêng tư hoặc bất kỳ tài nguyên nào được định danh bằng ID.

#### Lab: Insecure direct object references

![lab 4](/assets/img/20260714-access-control/image33.png)

Bài này mô tả là có lưu chat log trên hệ thống file của server và có thể truy xuất nó thông qua URL. Hoàn thành bài lab bằng cách tìm password của user `carlos` và đăng nhập.

![lab 4](/assets/img/20260714-access-control/image34.png)

Mình chat vài câu sau đó sử dụng chức năng `View Transcript` để xem lịch sử chat.

![lab 4](/assets/img/20260714-access-control/image35.png)

Ta có thể thấy được lịch sử chat của user `wiener` được lưu trên server là file `2.txt`, mình thử truy cập vào file `1.txt` xem thửu có gì hay không.

![lab 4](/assets/img/20260714-access-control/image36.png)

Và kết quả mình lấy dược password của user `carlos`. Đăng nhập và hoàn thành bài lab.

### 2.5 Access control vulnerabilities in multi-step processes

Với các chức năng nhạy cảm gồm nhiều bước, mỗi bước đều phải kiểm tra quyền và trạng thái hợp lệ. Nếu chỉ bước đầu tiên kiểm tra quyền còn các bước sau tin rằng user đã được xác thực đúng, attacker có thể gọi trực tiếp bước cuối để bỏ qua kiểm soát.

#### Lab: Multi-step process with no access control on one step

![lab 4](/assets/img/20260714-access-control/image37.png)

Bài lab này mô tả trang admin có nhiều bước để có thể thay đổi quyền. Để hoàn thành bài lab thì cần khai thác lỗi kiểm soát truy cập và nâng quyền của user `wiener`.

Đầu tiên thì mình vào admin panel với credentials đề bài cho để làm quen với các request. Thì với request nâng quyền thì sẽ phải thêm một bước xác nhận nữa mới thành công.

![lab 4](/assets/img/20260714-access-control/image38.png)

Với tính năng này thì sẽ thêm một tham số là `confirmed` để kiểm tra xem hành động của mình là `yes` hay `no`.

![lab 4](/assets/img/20260714-access-control/image39.png)

Thực hiện gửi request này để nâng quyền của user `wiener` với thêm tham số `confirmed = true` để request hợp lệ. Qua đó thành công nâng quyền và hoàn thành bài lab.

### 2.6 Referer-based access control

Header `Referer` không phải là cơ chế phân quyền đáng tin cậy vì client có thể sửa, xóa hoặc tự tạo header này. Nếu ứng dụng chỉ dựa vào `Referer` để quyết định request có đến từ trang admin hay không, attacker có thể giả mạo header và gọi trực tiếp chức năng nhạy cảm.

#### Lab: Referer-based access control

![lab 4](/assets/img/20260714-access-control/image40.png)

Bài này mô tả là chức năng admin được kiểm soát truy cập dựa trên header `referer`. Khai thác lỗi này để nâng quyền user `wiener` lên để hoàn thành bài lab.

![lab 4](/assets/img/20260714-access-control/image41.png)

Bài lab có cung cấp credential của `admin` mình truy cập vào và quan sát request upgrade quyền. Ta có thể thấy ở header `referer` trỏ về `/admin`.

Đăng nhập vào user `wiener` gửi request upgrade quyền này. Đầu tiên mình thử giữ nguyên header `referer` mà không thay đổi.

![lab 4](/assets/img/20260714-access-control/image43.png)

Kết quả là không thành công với lỗi 401. Thực hiện trỏ vào `/admin` ở `referer`, ta thành công upgrade quyền của user `wiener` qua đó hoàn thành bài lab.

![lab 4](/assets/img/20260714-access-control/image42.png)

## 3. How to prevent access control vulnerabilities

Để phòng tránh broken access control, nguyên tắc quan trọng nhất là mọi kiểm tra quyền phải được thực hiện ở phía server. Giao diện có thể ẩn button hoặc menu để cải thiện trải nghiệm, nhưng không được xem đó là một lớp bảo mật.

Một số hướng phòng tránh chính:

- Áp dụng deny by default: mặc định từ chối truy cập, chỉ cho phép khi có rule rõ ràng.
- Kiểm tra quyền trên mọi request, không chỉ ở bước đầu tiên của workflow.
- Kiểm tra quyền theo object, không chỉ kiểm tra user đã đăng nhập hay chưa.
- Không tin vào dữ liệu phía client để quyết định role hoặc quyền, ví dụ cookie, hidden field, query parameter.
- Dùng cơ chế phân quyền tập trung để tránh mỗi endpoint tự kiểm tra theo một cách khác nhau.
- Không dựa vào bảo mật bằng cách che giấu đường dẫn, vì URL có thể bị đoán, leak trong JavaScript, log, robots.txt hoặc source HTML.
- Với file hoặc object nhạy cảm, dùng định danh khó đoán vẫn chưa đủ; backend vẫn phải kiểm tra user hiện tại có quyền truy cập object đó không.
- Kiểm tra đầy đủ các HTTP method. Nếu `POST /admin/delete` bị chặn thì `GET`, `PUT`, `PATCH`, `DELETE` hoặc method override cũng cần được xử lý nhất quán.
- Không dùng `Referer` hoặc các header client-controlled làm cơ chế phân quyền chính.
- Log và monitor các hành vi bất thường như truy cập nhiều ID liên tiếp, đổi role trái phép, gọi endpoint admin từ user thường.

Về mặt thiết kế, nên mô hình hóa rõ ràng quan hệ giữa user, role, permission và resource. Ví dụ, thay vì chỉ kiểm tra `user.role == "admin"`, với dữ liệu riêng tư cần kiểm tra thêm object đó có thuộc về user hiện tại hoặc user hiện tại có permission cụ thể để xem object đó hay không.

Ví dụ kiểm tra chưa an toàn:

```text
GET /api/invoices/123
```

Nếu backend chỉ lấy invoice theo ID và trả về ngay, attacker có thể đổi `123` thành ID khác. Cách đúng là sau khi lấy invoice, server phải kiểm tra invoice đó thuộc về user hiện tại hoặc user hiện tại có quyền quản trị phù hợp.

Tóm lại, access control nên được xem là một lớp kiểm tra bắt buộc ở mọi boundary quan trọng: route, action, object và workflow. Khi một request có thể được sửa tùy ý từ phía client, backend phải là nơi đưa ra quyết định cuối cùng.
