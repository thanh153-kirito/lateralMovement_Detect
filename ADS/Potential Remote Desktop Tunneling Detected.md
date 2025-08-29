
---

# Potential Remote Desktop Tunneling Detected

## Goal

Phát hiện khả năng kẻ tấn công sử dụng **PowerShell Remoting** để thiết lập **tunnel cho Remote Desktop Protocol (RDP)** hoặc các dịch vụ khác. Điều này có thể cho phép attacker vượt qua firewall, che giấu kênh RDP và thực hiện **lateral movement** trong môi trường Windows.

## Categorization

* [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) / [Remote Services](https://attack.mitre.org/techniques/T1021/)
* [Execution](https://attack.mitre.org/tactics/TA0002/) / [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

## Strategy Abstract

Rule dựa trên việc theo dõi:

1. **Kết nối inbound đến WinRM/PowerShell Remoting (TCP 5985/5986)** từ nguồn bên ngoài.
2. Sau đó trong vòng 30 giây, một tiến trình mới được spawn bởi **wsmprovhost.exe**, ngoại trừ `conhost.exe`.

Khi xuất hiện pattern này, có khả năng host đã bị dùng để tạo **PowerShell Remoting session**, từ đó attacker có thể mở tunnel cho RDP hoặc các dịch vụ khác.

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

  * Port 5985/5986 là cổng mặc định của WinRM.
  * `wsmprovhost.exe` là process container cho PowerShell Remoting session.
  * Sự xuất hiện process mới từ `wsmprovhost.exe` cho thấy có command được thực thi qua session từ xa.

* **Ví dụ tấn công**:

  * Attacker dùng PowerShell để mở tunnel cho RDP:

    ```powershell
    Enter-PSSession -ComputerName target01 -Credential domain\user
    netsh interface portproxy add v4tov4 listenport=3389 connectaddress=127.0.0.1 connectport=3389
    ```
  * Từ đó, attacker có thể kết nối RDP qua kênh tunneling đã mở.

## Blind Spots and Assumptions

* Nếu attacker thiết lập tunnel qua công cụ khác (SSH, VPN, hoặc reverse shell) mà không dùng PowerShell Remoting → rule không phát hiện.
* Rule giả định rằng tất cả process spawn từ `wsmprovhost.exe` ngoại trừ `conhost.exe` đều đáng ngờ, nhưng một số tác vụ quản trị hợp pháp cũng có hành vi này.
* Không phát hiện trực tiếp “RDP session” mà chỉ nhận diện hành vi nền tảng (PowerShell Remoting + process execution).

## False Positives

* Quản trị viên sử dụng PowerShell Remoting để:

  * Quản lý từ xa (Deploy script, chạy command).
  * Tự động hoá (Ansible, SCCM, Intune).
* Một số hệ thống DevOps có thể thường xuyên spawn process từ `wsmprovhost.exe`.

## Validation

Để kiểm thử:

1. Từ máy A, kết nối tới máy B qua PowerShell Remoting:

   ```powershell
   Enter-PSSession -ComputerName target01 -Credential domain\user
   ```
2. Trên máy target, thực thi một lệnh mở port forwarding (ví dụ netsh).
3. Kiểm tra logs:

   * Kết nối inbound tới 5985/5986.
   * Tiến trình spawn từ `wsmprovhost.exe`.
4. Xác nhận rule trong SIEM sinh cảnh báo.

## Priority

* **Medium**: Khi phát hiện execution từ PowerShell Remoting.
* **High**: Nếu tiến trình spawn liên quan đến cấu hình mạng (vd: `netsh`, `plink`, `powershell.exe`) cho thấy khả năng tunneling.

## Response

1. Kiểm tra **source IP** kết nối tới WinRM.
2. Xác định process con spawn từ `wsmprovhost.exe`.
3. Liên hệ với admin để xác nhận hoạt động có hợp lệ.
4. Nếu nghi ngờ tấn công:

   * Cô lập host bị ảnh hưởng.
   * Kiểm tra cấu hình portproxy hoặc registry thay đổi liên quan RDP.
   * Thu thập logs PowerShell/WinRM để phân tích.
   * Reset credential bị sử dụng trong kết nối.

## Additional Resources

* MITRE ATT\&CK: [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
* MITRE ATT\&CK: [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/)
* Microsoft Docs: [About PowerShell Remoting](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/overview)

---


