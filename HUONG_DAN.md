# PII Shield – che / khôi phục thông tin cá nhân

Chạy: bấm đúp `Chay_PII_Shield.bat` (hoặc `python pii_shield.py`).

## Cách dùng
1. **Che**: kéo file `.doc / .docx / .xls / .xlsx / .pdf / .csv / .txt` vào → bấm **CHE THÔNG TIN**.
   Ra file `ten.masked.docx` / `ten.masked.pdf`: số điện thoại, email, CCCD, MST, STK, ngày sinh,
   địa chỉ, họ tên… được thay bằng `[[PHONE_001]]`, `[[EMAIL_001]]`…
   Bảng đối chiếu *token ↔ giá trị thật* lưu ở **`pii_vault.json`** (nằm trên máy bạn, không gửi đi đâu).
2. Đưa file đã che cho AI / người ngoài xử lý.
3. **Khôi phục**: nạp file bất kỳ có chứa các token (file đã che, hoặc file AI trả về `.docx/.pdf/.txt`)
   → bấm **KHÔI PHỤC** → ra `ten.restored.*` với thông tin thật.

Cùng một giá trị luôn ra cùng một token (qua nhiều file), nên file khác nhau vẫn khôi phục được
miễn dùng cùng một vault. **Đừng xóa / gửi đi file `pii_vault.json`** – mất nó là không khôi phục được.

## Excel / CSV
- Che **theo tiêu đề cột**: cột có tiêu đề *Họ tên, SĐT/Điện thoại, Email, Địa chỉ, CCCD/CMND, STK/Số tài khoản,
  MST, Ngày sinh…* thì **toàn bộ ô bên dưới** bị che (kể cả số điện thoại/CCCD gõ dạng số). Các ô khác vẫn được quét bình thường
  (vd. ô Ghi chú có "gọi 0988…"). Ghi chú, hình/ô văn bản và `mailto:` cũng được che; tên tác giả file/comment đổi thành "Author".
- Khôi phục xong, ô đã che trở thành **ô văn bản** (số điện thoại/CCCD mất kiểu số, ngày sinh dạng số-ngày sẽ không được che).
- **Ô công thức không bị che.** `.xls` cũ được đổi sang `.xlsx` qua Microsoft Excel. Tên sheet không bị che.

## PDF scan / ảnh chụp (OCR)
- Kéo file PDF scan hoặc ảnh `.png .jpg .tif .bmp` vào như bình thường → tool tự **OCR** (Tesseract, tiếng Việt + Anh),
  tìm thông tin cá nhân, **xóa thật các điểm ảnh** chỗ đó rồi viết token lên. Ảnh ra file `ten.masked.pdf`.
  Phần chữ còn lại được thêm lớp chữ ẩn để tìm kiếm / AI đọc được.
- Khôi phục PDF đã che chạy như PDF thường (ảnh gốc chỗ đó không phục hồi lại được, tool viết chữ thật lên chỗ trống).
- **OCR có thể đọc sai** (nhất là số, dấu tiếng Việt, chữ mờ/nghiêng) → chỗ đọc sai sẽ **không được che**. Luôn xem lại trang scan sau khi che.
  Scan càng nét (≥ 300 dpi) càng chính xác.
- Dữ liệu OCR nằm ở thư mục `tessdata` (cạnh `pii_shield.py`, cần `eng.traineddata`, `vie.traineddata`).
  Không cần cài Tesseract riêng.

## Dòng lệnh
```
python pii_shield.py mask    hop_dong.docx bao_cao.pdf --term "Công ty ABC" --term "Nguyễn Văn A"
python pii_shield.py restore hop_dong.masked.docx ket_qua_AI.txt
python pii_shield.py mask a.pdf --skip TAX,ADDR        # bỏ qua vài loại
python pii_shield.py mask a.docx --password            # mã hóa vault bằng mật khẩu
python pii_shield.py vault --reveal                    # xem vault
```

## Giới hạn cần biết
- **Tự nhận diện** theo mẫu (regex) nên có thể sót / che nhầm. Tên người chỉ bắt được khi đứng sau
  *Ông/Bà/Anh/Chị/Đại diện/Họ tên/Giám đốc…*; tên khác → thêm vào ô **Từ khóa riêng**. Luôn xem lại file đã che.
- Chữ ký, con dấu, ảnh chân dung trong file không bị che.
- **PDF**: chữ gốc bị xóa thật khỏi file (không chỉ phủ trắng). Token được vẽ lại bằng font Helvetica; khi khôi phục
  dùng Arial nên không giữ đúng font/in đậm gốc, và giá trị dài hơn token có thể bị thu nhỏ chữ. Nếu có cảnh báo
  "mất ký tự lân cận" (font lạ) thì kiểm tra lại trang đó.
- **Word**: giữ nguyên định dạng; che cả header/footer, bảng, ô văn bản, chú thích, link `mailto:`, tên tác giả trong thuộc tính file.
  `.doc` cũ được đổi sang `.docx` qua Microsoft Word (cần cài Word).
