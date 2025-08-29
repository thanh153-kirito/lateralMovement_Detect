
---

# WMI Incoming Lateral Movement

## Goal

Phát hiện việc kẻ tấn công sử dụng **Windows Management Instrumentation (WMI)** để thực thi tiến trình từ xa trên host Windows. Đây là kỹ thuật thường dùng trong **lateral movement** và có thể dẫn đến chiếm quyền kiểm soát hệ thống.

## Categorization

* [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) / [Remote Services](https://attack.mitre.org/techniques/T1021/)
* [Execution](https://attack.mitre.org/tactics/TA0002/) / [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)

## Strategy Abstract

Rule phát hiện chuỗi hành vi:

1. **Kết nối RPC đến dịch vụ Winmgmt (port 135, svchost.exe)** từ nguồn bên ngoài.
2. Ngay sau đó (<20s), có tiến trình mới được spawn bởi **WmiPrvSE.exe**.
   Rule có cơ chế loại trừ một số tool quản trị phổ biến (SCCM, Nessus, HP, csc.exe, msiexec.exe, appcmd.exe) và các tiến trình hệ thống hợp lệ để giảm false positives.

## Technical Context

* **Nguồn dữ liệu**: Elastic Defend, Sysmon.

* **Index sử dụng**:

  * `logs-endpoint.events.process-*`
  * `logs-endpoint.events.network-*`
  * `logs-windows.sysmon_operational-*`

* **Logic rule (EQL)**:

  ```eql
  sequence by host.id with maxspan = 20s
    [network where host.os.type == "windows" and process.name : "svchost.exe" and
     network.direction : ("incoming", "ingress") and destination.port == 135 and
     source.ip not in ("127.0.0.1", "::1")]
    [process where host.os.type == "windows" and event.type == "start" and
     process.parent.name : "WmiPrvSE.exe" and
     not (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System") and
     not (user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
          not event.dataset : ("windows.sysmon_operational", "windows.sysmon")) and
     not process.executable :
          ("?:\\Program Files\\HPWBEM\\Tools\\hpsum_swdiscovery.exe",
           "?:\\Windows\\CCM\\Ccm32BitLauncher.exe",
           "?:\\Windows\\System32\\wbem\\mofcomp.exe",
           "?:\\Windows\\Microsoft.NET\\Framework*\\csc.exe",
           "?:\\Windows\\System32\\powercfg.exe") and
     not (process.executable : "?:\\Windows\\System32\\msiexec.exe" and process.args : "REBOOT=ReallySuppress") and
     not (process.executable : "?:\\Windows\\System32\\inetsrv\\appcmd.exe" and process.args : "uninstall")]
  ```

* **Ý nghĩa**:

  * `svchost.exe` nhận kết nối RPC inbound tới port 135 → dấu hiệu của WMI call từ xa.
  * `WmiPrvSE.exe` spawn tiến trình con → thực thi lệnh qua WMI.
  * Loại trừ nhiều tool quản trị hợp pháp để giảm nhiễu.

* **Ví dụ tấn công**:

  * Attacker dùng `wmic` để chạy lệnh từ xa:

    ```cmd
    wmic /node:targethost process call create "cmd.exe /c whoami"
    ```
  * Hoặc dùng PowerShell:

    ```powershell
    Invoke-WmiMethod -Path Win32_Process -Name Create -ArgumentList "notepad.exe" -ComputerName targethost
    ```

## Blind Spots and Assumptions

* Nếu attacker dùng WMI qua DCOM nhưng inject trực tiếp vào tiến trình khác (không spawn child process từ `WmiPrvSE.exe`) → rule có thể bỏ sót.
* Nếu attacker dùng **asynchronous WMI event subscription** thay vì execution → rule không phát hiện.
* Rule giả định mọi tiến trình spawn từ `WmiPrvSE.exe` sau RPC đều đáng ngờ, trong khi một số hoạt động quản trị hợp pháp cũng có pattern tương tự.

## False Positives

* Quản trị viên sử dụng WMI cho:

  * Triển khai phần mềm qua SCCM.
  * Kiểm kê hệ thống qua Nessus hoặc công cụ asset discovery.
  * Một số phần mềm của HP, Microsoft.NET framework, powercfg.exe.
* Các false positives đã được rule loại trừ một phần nhưng có thể vẫn còn trong môi trường enterprise.

## Validation

Để kiểm thử:

1. Từ máy tấn công, thực hiện lệnh qua WMI:

   ```cmd
   wmic /node:targethost process call create "calc.exe"
   ```
2. Trên máy target:

   * Log **network inbound RPC (port 135)** từ máy attacker.
   * Log tiến trình con spawn từ **WmiPrvSE.exe**.
3. Xác nhận rule sinh cảnh báo trong SIEM.

## Priority

* **Medium**: Khi phát hiện tiến trình bất thường spawn từ WmiPrvSE.exe.
* **High**: Nếu tiến trình spawn là **cmd.exe**, **powershell.exe**, hoặc các tool tấn công như **mimikatz.exe**.

## Response

1. Kiểm tra **source IP** đã tạo kết nối RPC.
2. Xác định tiến trình được spawn bởi `WmiPrvSE.exe`.
3. Xác minh user context của tiến trình và so sánh với hoạt động quản trị hợp lệ.
4. Nếu nghi ngờ tấn công:

   * Cô lập host.
   * Thu thập logs để phân tích chi tiết.
   * Kiểm tra lateral movement từ source IP tới các host khác.
   * Reset hoặc revoke credential bị sử dụng.

## Additional Resources

* MITRE ATT\&CK: [WMI (T1047)](https://attack.mitre.org/techniques/T1047/)
* MITRE ATT\&CK: [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
* Microsoft Docs: [WMI Reference](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)

---


