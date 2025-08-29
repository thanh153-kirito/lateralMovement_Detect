
---

# PowerShell Script with Remote Execution Capabilities via WinRM

## Goal

Phát hiện hành vi sử dụng **PowerShell cmdlets** để chạy lệnh hoặc script trên **remote hosts** qua **WinRM (Windows Remote Management)**. Attacker thường lạm dụng `Invoke-Command`, `Enter-PSSession`, hoặc `Invoke-WmiMethod` với tham số **ComputerName**, cho phép thực thi lệnh từ xa mà không cần công cụ bên ngoài.

---

## Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)** → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
  * **Execution (TA0002)** → [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/)

---

## Strategy Abstract

* **WinRM** cung cấp giao diện quản trị từ xa qua PowerShell, WMI và WSMan.
* Cmdlets liên quan:

  * `Invoke-Command -ComputerName <host>` → chạy scriptblock từ xa.
  * `Enter-PSSession -ComputerName <host>` → mở phiên làm việc từ xa.
  * `Invoke-WmiMethod -ComputerName <host>` → gọi WMI methods trên host khác.
* Attacker dùng WinRM cho lateral movement thay vì SMB/PSEXEC để tránh detection.
* Rule này lọc ra khi script block có:

  * Cmdlets trên **và** chứa `ComputerName`.
  * Không phải chạy bởi **SYSTEM (S-1-5-18)**.
  * Không thuộc các thư mục hoặc framework hợp pháp (LogicMonitor, Icinga, SmartCardTools).
  * Không phải code nội bộ framework PowerShell (`Export-ModuleMember` exceptions).

---

## Technical Context

* **Nguồn dữ liệu**:

  * PowerShell logs (`Event ID 4104 – Script Block Logging`)
  * winlogbeat-\* / logs-windows.powershell\*
* **Query (KQL)**:

  ```kql
  event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    ("Invoke-WmiMethod" or "Invoke-Command" or "Enter-PSSession") and "ComputerName"
  ) and
  not user.id : "S-1-5-18" and
  not file.directory : (
    "C:\\Program Files\\LogicMonitor\\Agent\\tmp" or
    "C:\\Program Files\\WindowsPowerShell\\Modules\\icinga-powershell-framework\\cache" or
    "C:\\Program Files\\WindowsPowerShell\\Modules\\SmartCardTools\\1.2.2"
  ) and not
  powershell.file.script_block_text : (
    "Export-ModuleMember -Function @('Invoke-Expression''Invoke-Command')" and
    "function Invoke-Command {"
  )
  ```

---

## Blind Spots and Assumptions

* Không phát hiện nếu attacker:

  * Dùng `New-PSSession` rồi `Invoke-Command -Session`.
  * Dùng WMI hoặc DCOM qua PowerShell mà không có `ComputerName`.
  * Mã hóa/obfuscate script block để ẩn từ khóa.
* Phụ thuộc vào việc **PowerShell Script Block Logging được bật**.

---

## False Positives

* Admin hợp pháp sử dụng PowerShell remoting để quản lý hệ thống.
* Các framework giám sát hoặc automation (như Icinga, LogicMonitor) – đã có whitelist trong rule.
  👉 Nên whitelist thêm các tài khoản admin/domain service accounts hợp pháp.

---

## Validation

1. Trên một host A, chạy:

   ```powershell
   Invoke-Command -ComputerName <RemoteHost> -ScriptBlock { Get-Process }
   ```
2. Kiểm tra log trên host A:

   * PowerShell event 4104 chứa `Invoke-Command -ComputerName`.
3. Rule sẽ trigger vì cmdlet + ComputerName match.

---

## Priority

* **Low (21)** – vì:

  * WinRM có thể dùng hợp pháp cho quản trị.
  * Tuy nhiên nếu xuất hiện trên môi trường không ai dùng PowerShell Remoting → cực kỳ đáng ngờ.
* Độ ưu tiên có thể nâng lên **Medium/High** nếu:

  * Tài khoản không phải admin.
  * Nhiều host bị target trong thời gian ngắn.

---

## Response

1. Xác định **người dùng** và **máy nguồn** chạy cmdlet.
2. Kiểm tra host đích (`ComputerName`) → có task, process hoặc persistence nào bị tạo không.
3. Nếu nghi ngờ → thu thập full PowerShell transcript, network logs WinRM (port 5985/5986).
4. Chặn hoặc vô hiệu hóa WinRM nếu không cần dùng trong tổ chức.
5. Reset/rotate credentials nếu thấy lạm dụng account.

---

## Additional Resources

* [MITRE ATT\&CK – T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)
* [MITRE ATT\&CK – T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
* Microsoft Docs: [About Remote Commands](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands)

---

