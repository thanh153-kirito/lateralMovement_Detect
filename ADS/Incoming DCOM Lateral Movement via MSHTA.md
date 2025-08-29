

---

# Incoming DCOM Lateral Movement via MSHTA

## Goal

Phát hiện việc lạm dụng **DCOM (Distributed Component Object Model)** để thực thi lệnh từ xa thông qua **HTA Application COM Object (`mshta.exe`)**. Đây là kỹ thuật attacker thường dùng để **lateral movement** trong mạng nội bộ, đồng thời **né tránh detection** bằng cách lợi dụng binary hợp pháp của Windows.

## Categorization

* **MITRE ATT\&CK**:

  * Lateral Movement (TA0008) → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
  * Defense Evasion (TA0005) → [System Binary Proxy Execution (T1218)](https://attack.mitre.org/techniques/T1218/)

## Strategy Abstract

Rule phát hiện khi **`mshta.exe` được khởi chạy với tham số `-Embedding`**, sau đó có **network connection inbound từ remote host trên dynamic port (49152+)**.

* Tham số `-Embedding` thường cho thấy tiến trình **bị khởi chạy qua COM object từ xa**, thay vì user trực tiếp chạy.
* Đây là dấu hiệu rõ ràng của **DCOM lateral movement**: attacker từ máy A gọi COM object **HTA Application** trên máy B → dẫn đến việc `mshta.exe` chạy ngầm trên B.

## Technical Context

* **Nguồn dữ liệu**:

  * Elastic Defend (EDR)
  * Sysmon
  * Windows Security Event Logs

* **Index patterns**:

  * `winlogbeat-*`
  * `logs-endpoint.events.process-*`
  * `logs-endpoint.events.network-*`
  * `logs-windows.sysmon_operational-*`

* **Logic Rule (EQL)**:

  ```eql
  sequence with maxspan=1m
    [process where host.os.type == "windows" and event.type == "start" and
       process.name : "mshta.exe" and process.args : "-Embedding"
    ] by host.id, process.entity_id
    [network where host.os.type == "windows" and event.type == "start" and process.name : "mshta.exe" and
       network.direction : ("incoming", "ingress") and network.transport == "tcp" and
       source.port > 49151 and destination.port > 49151 and source.ip != "127.0.0.1" and source.ip != "::1"
    ] by host.id, process.entity_id
  ```

* **Ý nghĩa kỹ thuật**:

  * `mshta.exe` thường dùng để thực thi file **HTA script (HTML Application)**.
  * Với flag `-Embedding`, nó bị gọi bởi COM → dấu hiệu **không phải user click mà bị trigger từ xa**.
  * Kết hợp traffic inbound TCP high port (49152+) → gợi ý rằng tiến trình này đang được điều khiển qua DCOM.

* **Ví dụ tấn công**:

  ```powershell
  # Attacker dùng PowerShell để gọi COM object HTA từ xa
  $hta = [activator]::CreateInstance([type]::GetTypeFromProgID("htafile", "TARGETHOST"))
  $hta.Execute("calc.exe")
  ```

  → Trên TARGETHOST sẽ thấy `mshta.exe -Embedding` + network traffic DCOM.

## Blind Spots and Assumptions

* Rule này **chỉ phát hiện DCOM qua HTA Application**. Nếu attacker dùng DCOM object khác (Excel, MMC, ShellWindows, etc.) thì rule sẽ **không bắt được**.
* Có thể bị bỏ sót nếu attacker tunneling DCOM qua SMB/HTTP proxy.
* Một số tool quản trị hợp pháp cũng có thể trigger hành vi này.

## False Positives

* Quản trị viên hoặc ứng dụng hợp pháp gọi COM object HTA từ xa (hiếm gặp).
* Một số phần mềm cũ hoặc tự động hóa nội bộ có thể sử dụng cơ chế này.
  👉 Do đó cần **baseline môi trường**, nếu thấy máy bất ngờ spawn `mshta.exe -Embedding` từ DCOM remote thì khả năng cao là malicious.

## Validation

1. Trên máy attacker, chạy:

   ```powershell
   $hta = [activator]::CreateInstance([type]::GetTypeFromProgID("htafile", "TARGET"))
   $hta.Execute("notepad.exe")
   ```
2. Trên máy TARGET, kiểm tra event:

   * Process: `mshta.exe -Embedding`
   * Network inbound từ máy attacker với cổng >49151
3. Đảm bảo rule bắn alert đúng như mong đợi.

## Priority

* **High (73)** vì:

  * Hành vi **hiếm khi xuất hiện hợp pháp**.
  * Thường là **dấu hiệu tấn công lateral movement** bằng DCOM.

## Response

1. Xác định host nguồn gửi DCOM request.
2. Kiểm tra tiến trình con của `mshta.exe` (ví dụ: PowerShell, cmd, custom payload).
3. Phân tích toàn bộ command line / script được mshta thực thi.
4. Nếu xác nhận malicious:

   * Cách ly host nguồn và đích.
   * Xóa persistence (service, scheduled task, registry) nếu có.
   * Reset tài khoản AD liên quan.

## Additional Resources

* [MITRE ATT\&CK – T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)
* [MITRE ATT\&CK – T1218 System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
* Microsoft Docs – [About DCOM](https://learn.microsoft.com/en-us/windows/win32/com/distributed-com)

---


