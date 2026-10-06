# NetworkAutomation 6.9.0 Hotfix16 - LAN discovery speed & accuracy

## Vấn đề
- Hộp thoại "IP đang dùng trong cùng mạng" có thể đứng lâu ở 0/— dù tiến trình nền vẫn chạy.
- Giai đoạn sơ bộ chạy nhiều nguồn chậm nối tiếp nhau trước khi bắt đầu ICMP.
- Reverse DNS/NetBIOS có thể chặn lâu trên từng IP.
- Mỗi IP online có thể tạo một tiến trình `arp`, gây chậm và tốn tài nguyên.
- Số "IP đang dùng" khi đang quét dùng `max()` giữa ARP và ICMP nên có thể thấp hơn số IP thực tế khi hai tập khác nhau.

## Sửa đổi
1. Fast preliminary: chỉ lấy ARP/neighbor trước để UI có kết quả sớm.
2. DHCP, mDNS, SSDP chạy song song ở pha hợp nhất sau ICMP.
3. Reverse DNS có timeout chặt và enrich hostname song song.
4. Dùng ARP snapshot cache ngắn hạn thay vì spawn `arp` cho từng host.
5. Khi quét, đếm hợp của IP thấy qua LAN thụ động và ICMP thay vì `max()`.
6. Modal discovery tự refresh mỗi 1 giây khi RUNNING/QUEUED; chip nền poll 1.5 giây.
7. Hiển thị "đang chuẩn bị" thay vì dấu — khi chưa có tổng tiến độ.

## Kỳ vọng
- Trạng thái/progress xuất hiện nhanh hơn rõ rệt.
- Ít process con hơn khi quét /24.
- Số IP đang dùng trong lúc quét sát thực tế hơn.
- Thiết bị chặn ping vẫn được giữ qua ARP/DHCP/mDNS/SSDP.

## Integrity fix
- Cập nhật `RELEASE_MANIFEST.json` theo đúng hash của các file Hotfix16 đã thay đổi.
- Bổ sung test/report Hotfix16 vào tập file bắt buộc của `VERIFY_RELEASE.py`.
- Đồng bộ nhãn OneClick/BUILD_INFO thành Hotfix16 để tránh hiển thị nhầm Hotfix15.
- Không thay đổi hoặc reset database/key của người dùng.
