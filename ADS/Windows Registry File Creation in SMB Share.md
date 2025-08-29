
---

# Windows Registry File Creation in SMB Share

## Goal

Phát hiện hành vi tạo hoặc chỉnh sửa file hive của Windows Registry (SAM, SYSTEM, SECURITY, NTUSER.DAT, v.v.) trong thư mục chia sẻ SMB. Đây có thể là dấu hiệu kẻ tấn công đang sao chép registry hive để lấy thông tin đăng nhập và di chuyển sang hệ thống khác.

## Categorization

* [Credential Access](https://attack.mitre.org/tactics/TA0006/) / [OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
* [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) / [Remote Services](https://attack.mitre.org/techniques/T1021/)

## Strategy Abstract

Detection dựa trên việc theo dõi file registry hive (có header `regf`) với kích thước trung bình (\~≥30KB), được tạo bởi tiến trình **System (PID 4)**, trong môi trường Windows, và được ghi ra **SMB share**. Các đường dẫn và file hợp lệ (profile, settings, temporary offreg) đã được loại trừ để giảm cảnh báo giả.

## Technical Context

* **Nguồn dữ liệu**: Elastic Defend (`logs-endpoint.events.file-*`)
* **Logic rule (EQL)**:

  ```eql
  file
  where host.os.type == "windows" and event.type == "creation" and
    file.Ext.header_bytes : "72656766*" and file.size >= 30000 and
    process.pid == 4 and user.id : ("S-1-5-21*", "S-1-12-1-*") and
    not file.path : (
      "?:\\*\\UPM_Profile\\NTUSER.DAT",
      "?:\\*\\UPM_Profile\\NTUSER.DAT.LASTGOODLOAD",
      "?:\\*\\UPM_Profile\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat*",
      "?:\\Windows\\Netwrix\\Temp\\????????.???.offreg",
      "?:\\*\\AppData\\Local\\Packages\\Microsoft.*\\Settings\\settings.dat*"
    )
  ```
* **Ý nghĩa**:

  * Header `72656766` tương ứng với chữ ký `regf` trong file registry hive.
  * `process.pid == 4` → tiến trình **System** (thực hiện I/O cấp kernel).
  * `user.id` dạng `S-1-5-21*` hoặc `S-1-12-1-*` → người dùng cục bộ hoặc domain.
* **Ví dụ tấn công**:

  * Kẻ tấn công dump `SAM` hive và sao chép qua `\\attacker\share\sam.reg`.
  * Sau đó sử dụng công cụ như **mimikatz** hoặc **secretsdump.py** để trích xuất hash mật khẩu.

## Blind Spots and Assumptions

* Rule chỉ phát hiện registry hive có kích thước >30KB. Nếu attacker nén/fragment hive → có thể tránh bị phát hiện.
* Nếu exfiltration qua cơ chế khác (HTTP, RDP clipboard, cloud sync) → rule không phát hiện.
* Một số ứng dụng backup hợp pháp có thể thao tác hive nhưng ghi ra SMB share với pattern khác.

## False Positives

* Sao lưu profile người dùng trong môi trường VDI (Citrix, UPM).
* Ứng dụng quản trị hợp pháp (Netwrix, Microsoft apps) tạo/ghi hive trong quá trình backup hoặc cấu hình roaming profile.
* Các tool quản trị hợp pháp tạo file offreg (`.offreg`) đã được loại trừ, nhưng vẫn có thể phát sinh FP nếu phần mềm backup không nằm trong danh sách loại trừ.

## Validation

Để kiểm thử:

1. Trên Windows host, dump một hive registry (ví dụ SAM):

   ```powershell
   reg save HKLM\SAM \\attacker\share\sam.reg
   ```
2. Đảm bảo file `sam.reg` được ghi ra SMB share.
3. Trong Elastic SIEM, xác nhận rule sinh cảnh báo.

## Priority

* **Medium** khi phát hiện file hive được tạo, nhưng chưa rõ mục đích.
* **High** nếu xác nhận file chứa `SAM`, `SYSTEM`, hoặc `SECURITY` hive được ghi ra SMB share không hợp lệ.

## Response

1. Kiểm tra file path và SMB share đích (`file.path`).
2. Xác định user SID (`user.id`) và tiến trình sinh ra hành vi.
3. Kiểm tra host đích để xác nhận có hành vi dump registry hive.
4. Nếu nghi ngờ tấn công:

   * Cô lập host bị ảnh hưởng.
   * Thu thập registry hive dump để phân tích.
   * Reset mật khẩu các tài khoản có nguy cơ bị lộ.
   * Kiểm tra lateral movement từ share đích.

## Additional Resources

* MITRE ATT\&CK: [OS Credential Dumping (T1003)](https://attack.mitre.org/techniques/T1003/)
* Microsoft Docs: [Registry Hive Files](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
* Elastic Security Rules: [Prebuilt Detection Rules](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)

---

