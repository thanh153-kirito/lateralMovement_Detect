

---

# Incoming Execution via PowerShell Remoting

## Goal

Phát hiện hành vi thực thi lệnh từ xa thông qua **PowerShell Remoting** trên Windows. Kỹ thuật này cho phép chạy lệnh PowerShell trên máy tính khác và thường được kẻ tấn công lợi dụng để thực hiện **lateral movement** trong mạng.

## Categorization

* [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) / [Remote Services](https://attack.mitre.org/techniques/T1021/)
* [Execution](https://attack.mitre.org/tactics/TA0002/) / [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

## Strategy Abstract

Rule phát hiện khi có:

1. **Kết nối mạng inbound** tới port **5985/5986** (WinRM/PowerShell Remoting).
2. Ngay sau đó (<30s), một tiến trình mới được spawn bởi **wsmprovhost.exe**, ngoại trừ `conhost.exe` hợp lệ.
   Điều này cho thấy có khả năng một phiên PowerShell Remoting được mở và thực thi lệnh trên host.

## Technical Context

* **Nguồn dữ liệu**: Elastic Defend, Sysmon.

* **Index sử dụng**:

  * `winlogbeat-*`
  * `logs-endpoint.events.process-*`
  * `logs-endpoint.events.network-*`
  * `logs-windows.sysmon_operational-*`

* **Logic rule (EQL)**:

  ```eql
  sequence by host.id with maxspan = 30s
    [network where host.os.type == "windows" and
     network.direction : ("incoming", "ingress") and
     destination.port in (5985, 5986) and
     source.ip not in ("127.0.0.1", "::1")]
    [process where host.os.type == "windows" and
     event.type == "start" and process.parent.name : "wsmprovhost.exe" and
     not process.executable : "?:\\Windows\\System32\\conhost.exe"]
  ```

* **Ý nghĩa**:

  * PowerShell Remoting sử dụng WinRM (TCP 5985 - HTTP, 5986 - HTTPS).
  * `wsmprovhost.exe` là tiến trình host được tạo khi một lệnh PowerShell từ xa được thực thi.
  * Bất kỳ tiến trình con nào spawn từ `wsmprovhost.exe` ngoài `conhost.exe` đều đáng chú ý.

* **Ví dụ tấn công**:

  * Attacker dùng PowerShell Remoting:

    ```powershell
    Enter-PSSession -ComputerName targethost -Credential domain\user
    Invoke-Command -ComputerName targethost -ScriptBlock { Get-Process }
    ```

## Blind Spots and Assumptions

* Rule không phát hiện nếu attacker sử dụng cơ chế **WinRM tunneling hoặc proxy** thay vì kết nối trực tiếp 5985/5986.
* Nếu attacker tải mã độc nhưng inject vào tiến trình khác thay vì spawn process con từ `wsmprovhost.exe` → rule có thể bỏ sót.
* Rule giả định rằng bất kỳ tiến trình spawn từ `wsmprovhost.exe` (ngoại trừ `conhost.exe`) đều khả nghi, nhưng nhiều hoạt động quản trị cũng có pattern tương tự.

## False Positives

* Quản trị viên sử dụng **PowerShell Remoting** để:

  * Quản lý và cấu hình máy chủ.
  * Triển khai script automation (Ansible, SCCM, SaltStack).
* Các hoạt động DevOps hợp pháp có thể tạo ra nhiều noise.
* Cần baseline hoạt động PowerShell Remoting hợp lệ trong môi trường để giảm cảnh báo giả.

## Validation

Để kiểm thử:

1. Từ máy tấn công (hoặc admin), thực hiện PowerShell Remoting:

   ```powershell
   Enter-PSSession -ComputerName target01 -Credential domain\user
   Get-Service
   ```
2. Trên target:

   * Ghi nhận network inbound trên port 5985/5986.
   * Xác minh tiến trình spawn từ **wsmprovhost.exe**.
3. Kiểm tra SIEM để xác nhận rule đã sinh cảnh báo.

## Priority

* **Medium**: Khi có execution thông qua `wsmprovhost.exe` nhưng không rõ hành vi.
* **High**: Nếu tiến trình spawn là `cmd.exe`, `powershell.exe`, hoặc công cụ tấn công (vd: `mimikatz.exe`).

## Response

1. Xác định **nguồn kết nối** (`source.ip`) và **tài khoản** sử dụng.
2. Kiểm tra tiến trình con spawn từ `wsmprovhost.exe` để biết attacker đã chạy lệnh gì.
3. Liên hệ với admin để xác nhận hoạt động có hợp lệ không.
4. Nếu nghi ngờ tấn công:

   * Cô lập host bị ảnh hưởng.
   * Thu thập log PowerShell/WinRM để phân tích.
   * Kiểm tra lateral movement từ source IP tới các host khác.
   * Reset hoặc revoke credential được sử dụng trong kết nối.

## Additional Resources

* MITRE ATT\&CK: [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
* MITRE ATT\&CK: [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/)
* Microsoft Docs: [PowerShell Remoting](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/overview)

---

