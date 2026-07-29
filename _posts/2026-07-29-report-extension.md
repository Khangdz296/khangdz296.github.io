---
title: Extension - XSS Context Analyzer
date: 2026-07-29 10:00:00 +0700
categories:
tags:
---

## 1. Ý tưởng

Trong quá trình làm lab và giải các chall ctf thì e gặp vuln XSS khá thường xuyên. Lúc bắt đầu khai thác lỗ hổng em thường xác định context XSS này bằng cách thủ công tự thử từng request một.

Do đó em mới nảy ra ý tưởng là làm một extension phân tích context của XSS. Ý tưởng sẽ là extension giúp e biết được context của XSS này một cách tự động, ví dụ như dựa vào request và response, extension sẽ xác định điểm bị reflection và phân tích xem nó nằm ở context nào (ví dụ như: HTML text, JS element, event tag...)

## 2. Extension

Extension sẽ tự động nhận traffic từ Proxy và Repeater, có thể giới hạn trong Burp scope. Với các request có input được hỗ trợ, extension chạy `Passive Analysis` và chỉ hiển thị các request trong Captured Requests khi phát hiện ít nhất một reflection.

![img](/assets/img/tmp/image1.png)

Bước tiếp theo e sẽ click chọn 1 request để phân tích và chuyển sang tab `Analysis`. Thì ở tab này nó sẽ phân tích các tham số được reflection trong response, nó cũng sẽ phân tích đang ở context nào và sẽ có các dòng mô tả ở dưới.

![img](/assets/img/tmp/image2.png)

Tiếp theo thì đến bước phân tích các dạng kí tự đặc biệt liên quan đến context hiện tại bằng chức năng `Run Active Analysis`. Sau khi phân tích xong thì nó sẽ hiện kết quả ở tab `Character Map`. Ở bước này thì nó sẽ thử xem các kí tự này có bị escape, filter hay encode gì không. Qua đó đưa ra kết luận cho context hiện tại.

![img](/assets/img/tmp/image3.png)

Trong ví dụ này, probe `\'` được trả về với số lượng backslash chẵn và tạo ra chuyển trạng thái từ JS Single-Quoted String sang JS Expression, nó sẽ hiển thị cảnh báo để mình ưu tiên kiểm tra thủ công trường hợp này.

Cuối cùng là tab `Suggestions` sẽ đề xuất các bước kiểm thử tiếp theo phù hợp với context đã quan sát.

![img](/assets/img/tmp/image4.png)

## 3. Điểm hạn chế

Khi bắt tay vào làm thì em mới bắt đầu gặp khó khăn về việc theo dõi các trường hợp như redirect chain, stored XSS, DOM XSS hoặc runtime data flow phía client. Do đó thì extension hiện tại của e chỉ phát hiện được đa số là dạng input được reflect ngay trong response.

Cũng như là chưa tự động hoàn nó chỉ giúp được một phần là xác định context thôi còn sau đó khi tiến hành khai thác thêm thì vẫn có thể sẽ gặp những lớp filter khác. Các trường hợp như bị CSP block cũng chưa được triển khai.

## Một vài trường hợp khác

![img](/assets/img/tmp/image5.png)

![img](/assets/img/tmp/image6.png)
