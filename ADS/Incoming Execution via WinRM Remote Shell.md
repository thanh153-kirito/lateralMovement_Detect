
# Incoming Execution via WinRM Remote Shell

## Goal

Phát hiện việc thực thi lệnh từ xa trên máy Windows thông qua Windows Remote Management (WinRM) Remote Shell. Đây có thể là hành vi **lateral movement** khi attacker sử dụng WinRM để thực thi lệnh từ hệ thống khác.

## Categorization

* [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) / [Remote Services](https://attack.mitre.org/techniques/T1021/)

## Strategy Abstract

Rule kết hợp dữ liệu **network** và **process** để phát hiện:

1. **Kết nối mạng đến WinRM (TCP 5985/5986)** trên host Windows (PID 4).
2. **Tiến trình con** được khởi tạo bởi `winrshost.exe`, ngoại trừ `conhost.exe`.
   Chuỗi này trong vòng **30 giây** cho thấy khả năng có phiên WinRM remote shell được sử dụng để chạy lệnh.

## Technical Context

* **Nguồn dữ liệu**: Elastic Defend, Sysmon, Winlogbeat.

* **Index sử dụng**:

  * `winlogbeat-*`
  * `logs-endpoint.events.process-*`
  * `logs-endpoint.events.network-*`
  * `logs-windows.sysmon_operational-*`

* **Logic rule (EQL)**:

  ```eql
  sequence by host.id with maxspan=30s
    [network where host.os.type == "windows" and process.pid == 4 and network.direction : ("incoming", "ingress") and
     destination.port in (5985, 5986) and source.ip != "127.0.0.1" and source.ip != "::1"]
    [process where host.os.type == "windows" and
     event.type == "start" and process.parent.name : "winrshost.exe" and not process.executable : "?:\\Windows\\System32\\conhost.exe"]
  ```

* **Ý nghĩa**:

  * `network.direction: incoming` với port 5985/5986 → Kết nối WinRM từ xa.
  * `process.parent.name: winrshost.exe` → Cho thấy WinRM khởi tạo tiến trình con để thực thi lệnh.
  * Loại trừ `conhost.exe` vì thường được spawn hợp lệ để xử lý console.

* **Ví dụ tấn công**:

  * Attacker dùng `Invoke-Command` hoặc `Enter-PSSession` trong PowerShell để chạy lệnh trên host đích.
  * Câu lệnh mẫu từ máy tấn công:

    ```powershell
    Invoke-Command -ComputerName target01 -ScriptBlock { ipconfig /all } -Credential domain\user
    ```

## Blind Spots and Assumptions

* Nếu attacker dùng WinRM qua proxy hoặc tunneling khác (ví dụ: HTTP relay) mà không trực tiếp trên 5985/5986, rule không phát hiện.
* Nếu attacker inject vào `winrshost.exe` thay vì spawn process con → rule có thể bỏ sót.
* Rule giả định mọi hoạt động WinRM execution đều đáng ngờ, trong khi nhiều tổ chức dùng WinRM cho quản trị hệ thống.

## False Positives

* Các hoạt động hợp pháp từ **administrators** hoặc tool quản trị (SCCM, Ansible, SaltStack, v.v.) dùng WinRM để triển khai lệnh/script.
* Hoạt động **PowerShell Remoting** do admin thực hiện thường xuyên.
* Baseline môi trường cần xác định đâu là traffic quản trị hợp lệ để loại trừ.

## Validation

Để kiểm thử:

1. Trên máy attacker, chạy lệnh từ PowerShell:

   ```powershell
   Invoke-Command -ComputerName target01 -ScriptBlock { whoami } -Credential domain\user
   ```
2. Trên target, kiểm tra logs:

   * Sự kiện **network incoming** tới port 5985/5986.
   * Tiến trình con được spawn bởi `winrshost.exe`.
3. Xác nhận rule trong SIEM tạo cảnh báo.

## Priority

* **Medium**: Khi chỉ có kết nối WinRM remote shell.
* **High**: Nếu tiến trình thực thi là công cụ nhạy cảm (vd: `cmd.exe`, `powershell.exe`, `mimikatz.exe`).

## Response

1. Xác định **nguồn kết nối** (source IP) và **người dùng** (user context).
2. Kiểm tra tiến trình con spawn từ `winrshost.exe` để biết attacker chạy lệnh gì.
3. Liên hệ admin để xác nhận hoạt động có hợp lệ không.
4. Nếu nghi ngờ tấn công:

   * Cô lập host bị ảnh hưởng.
   * Thu thập log PowerShell/WinRM để phân tích.
   * Kiểm tra lateral movement sang các hệ thống khác.
   * Reset hoặc revoke credential bị sử dụng.

## Additional Resources

* MITRE ATT\&CK: [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
* Microsoft Docs: [Windows Remote Management](https://learn.microsoft.com/en-us/windows/win32/winrm/portal)
* Elastic Security: [Prebuilt Rules Reference](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)

