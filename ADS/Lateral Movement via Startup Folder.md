

---

# Lateral Movement via Startup Folder

## Goal

Phát hiện hành vi **tạo hoặc chỉnh sửa file trong thư mục Startup của Windows** thông qua kênh **RDP mapped drive** hoặc **SMB share**, cho thấy khả năng attacker đang cố gắng **di chuyển lateral** và đồng thời **tạo persistence** trên máy nạn nhân.

---

## Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)** → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
  * **Persistence (TA0003)** → [Boot or Logon Autostart Execution (T1547)](https://attack.mitre.org/techniques/T1547/)

---

## Strategy Abstract

* Khi attacker RDP vào hệ thống và **mount TSClient drive** hoặc sử dụng **SMB** để copy file:

  * **Process liên quan**: `mstsc.exe` (Remote Desktop Client) hoặc **PID 4** (System process cho SMB).
  * **Hành vi bất thường**: tạo/chỉnh sửa file trong **Startup Folder**:

    ```
    C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
    C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\
    ```
* Khi nạn nhân đăng nhập lại hoặc khởi động lại máy → payload trong folder Startup sẽ chạy tự động, đảm bảo persistence.

---

## Technical Context

* **Nguồn dữ liệu**:

  * Elastic Endgame
  * Elastic Defend
  * Sysmon (Event ID 11 – File Create, ID 2 – File Change)
  * Microsoft Defender for Endpoint
  * SentinelOne

* **Index patterns**:

  * `logs-endpoint.events.file-*`
  * `logs-windows.sysmon_operational-*`
  * `logs-m365_defender.event-*`
  * `logs-sentinel_one_cloud_funnel.*`
  * `endgame-*`
  * `winlogbeat-*`

* **Logic Rule (EQL)**:

  ```eql
  file where host.os.type == "windows" and event.type in ("creation", "change") and
    (process.name : "mstsc.exe" or process.pid == 4) and
    file.path : ("?:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
                 "?:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
  ```

---

## Blind Spots and Assumptions

* Rule này giả định attacker sử dụng **mstsc.exe** hoặc SMB (PID 4) để copy file.
* Nếu attacker dùng **PSExec, WMI, WinRM hoặc custom tool** để ghi file vào Startup folder → có thể bypass detection.
* Không phát hiện nếu persistence được tạo bằng registry run keys, services hoặc scheduled tasks.

---

## False Positives

* Admin/IT team đôi khi copy script hợp pháp vào Startup folder để triển khai nhanh ứng dụng hoặc config.
* Một số phần mềm cũ cũng tự tạo shortcut hoặc binary trong Startup folder.
  👉 Nên baseline các ứng dụng/doanh nghiệp sử dụng → ví dụ: phần mềm quản lý IT, công cụ deploy script nội bộ.

---

## Validation

1. Từ máy A, kết nối RDP đến máy B với tùy chọn chia sẻ ổ đĩa (TSClient).
2. Trên máy A, copy một script/test file vào:

   ```
   \\tsclient\C\Users\<User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.bat
   ```

   hoặc vào:

   ```
   C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe
   ```
3. Kiểm tra log trên máy B:

   * File creation/change trong Startup folder.
   * Process liên quan: `mstsc.exe` hoặc PID 4.
4. Rule trigger.

---

## Priority

* **High (73)**

  * Startup folder persistence kết hợp lateral movement rất đáng ngờ.
  * Thường không xảy ra trong hoạt động quản trị hợp pháp hiện đại (đa số tool quản lý dùng Group Policy, SCCM, Intune).
  * Cần điều tra ngay khi thấy alert.

---

## Response

1. Kiểm tra file được tạo trong Startup folder (hash, nội dung, chữ ký số).
2. Xác định **remote source (IP, user)** → xem có khớp với hoạt động admin hợp pháp không.
3. Xem lịch sử RDP logins (`Security Event ID 4624`, LogonType=10).
4. Nếu file đáng ngờ → isolate host, xóa persistence, điều tra lateral movement path.
5. Correlate với các alert khác: Remote File Copy, Remote Service Install, Remote Scheduled Task.

---

## Additional Resources

* [MITRE ATT\&CK – T1547 Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
* [Microsoft Docs – Windows Startup Folder](https://learn.microsoft.com/en-us/windows/deployment/windows-10-startup-settings)
* Sysmon Event ID 11 – File Creation

---

