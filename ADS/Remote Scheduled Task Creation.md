

---

# Remote Scheduled Task Creation

## Goal

Phát hiện việc **tạo Scheduled Task từ xa** trên máy đích thông qua dịch vụ Task Scheduler.

* Đây là một kỹ thuật phổ biến để **lateral movement** hoặc **remote code execution**, vì attacker có thể tạo scheduled task trên máy từ xa để chạy lệnh/malware.

---

## Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)** → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
  * **Execution (TA0002)** → [Scheduled Task/Job (T1053)](https://attack.mitre.org/techniques/T1053/)

---

## Strategy Abstract

* Khi attacker (hoặc admin) tạo scheduled task từ xa:

  1. **Network activity**: Dịch vụ Task Scheduler (`svchost.exe` chạy `Schedule` service) nhận inbound RPC call từ máy nguồn → kết nối TCP với port động (49152+).
  2. **Registry modification**: Windows ghi chi tiết task vào registry dưới key:

     ```
     HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\<GUID>\Actions
     ```

Rule correlation:

* **Bước 1**: incoming connection đến `svchost.exe` với port >= 49152 (dynamic RPC).
* **Bước 2**: ngay sau đó (≤ 1 phút), có thay đổi registry value `"Actions"` trong TaskCache.
* Nếu chuỗi này xảy ra → task mới đã được tạo từ remote host.

---

## Technical Context

* **Nguồn dữ liệu**:

  * Elastic Defend
  * Sysmon
  * Windows event forwarding

* **Index patterns**:

  * `logs-endpoint.events.registry-*`
  * `logs-endpoint.events.network-*`
  * `logs-windows.sysmon_operational-*`
  * `winlogbeat-*`

* **Logic Rule (EQL)**:

  ```eql
  sequence by host.id, process.entity_id with maxspan = 1m
     [network where host.os.type == "windows" and process.name : "svchost.exe" and
     network.direction : ("incoming", "ingress") and source.port >= 49152 and destination.port >= 49152 and
     source.ip != "127.0.0.1" and source.ip != "::1"
     ]
     [registry where host.os.type == "windows" and event.type == "change" and registry.value : "Actions" and
      registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions"]
  ```

* **Ý nghĩa kỹ thuật**:

  * Dùng **correlation trong 1 phút** → đảm bảo rằng registry change liên quan đến chính network connection vừa tới.
  * Điều kiện network port ≥ 49152 → đặc trưng của **dynamic RPC port** mà Task Scheduler sử dụng.

---

## Blind Spots and Assumptions

* Nếu attacker tạo scheduled task **local** (chạy `schtasks.exe` trực tiếp trên host), rule này sẽ không phát hiện (chỉ detect remote).
* Nếu task được tạo từ xa nhưng qua **WMI** hoặc tool tùy chỉnh (không dùng Task Scheduler service chuẩn) → có thể bypass detection.
* Giả định rằng:

  * Sysmon hoặc Elastic Defend log đầy đủ registry changes và network events.
  * Task Scheduler luôn ghi xuống key `TaskCache\Tasks\<GUID>\Actions` khi có task mới.

---

## False Positives

* Hệ thống quản trị hợp pháp (SCCM, PDQ Deploy, Intune, patch management tools) tạo scheduled task từ xa.
* Các agent bảo mật hoặc phần mềm monitoring (AV/EDR) có thể deploy update/job qua scheduled tasks.
  👉 Giảm FP bằng cách baseline **các ứng dụng/quy trình quản trị hợp pháp**.

---

## Validation

1. Từ máy A, chạy lệnh tạo task từ xa trên máy B:

   ```cmd
   schtasks /create /s <RemoteHost> /u <Domain\User> /p <Password> /sc once /tn "RemoteTaskTest" /tr "cmd.exe /c calc.exe"
   ```
2. Trên máy B:

   * `svchost.exe` (`Schedule` service) nhận inbound RPC connection (port > 49152).
   * Registry được update:

     ```
     HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\<GUID>\Actions
     ```
3. Rule trigger alert.

---

## Priority

* **Medium (47)**

  * Đây là hành vi **thực sự nguy hiểm** nếu xảy ra ngoài quy trình admin hợp pháp.
  * Nhưng mức độ **false positive cao** trong môi trường có nhiều công cụ quản lý IT.

---

## Response

1. Kiểm tra Scheduled Task mới được tạo (tên, command, user account).
2. Xác định **remote source IP và user** khởi tạo connection.
3. Correlate với các sự kiện khác:

   * Remote File Copy
   * Remote Service Creation / RPC Execution
   * Admin logins vào cùng timeframe
4. Nếu không khớp với hoạt động hợp pháp → isolate host và điều tra lateral movement.

---

## Additional Resources

* [MITRE ATT\&CK – T1053 Scheduled Task](https://attack.mitre.org/techniques/T1053/)
* [Microsoft Docs – Task Scheduler Architecture](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
* Sysmon Event ID 13 – Registry value set

---


