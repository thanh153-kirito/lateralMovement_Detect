
---

# Service Command Lateral Movement

## Goal

Phát hiện việc sử dụng **`sc.exe`** để tạo, chỉnh sửa hoặc khởi động dịch vụ từ xa trên các host Windows. Đây là một kỹ thuật phổ biến để attacker thực hiện **lateral movement**, persistence hoặc remote execution.

## Categorization

* **MITRE ATT\&CK**:

  * [Lateral Movement - Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
  * [Persistence - Create or Modify System Process (T1543)](https://attack.mitre.org/techniques/T1543/)
  * [Execution - System Services (T1569)](https://attack.mitre.org/techniques/T1569/)

## Strategy Abstract

Rule giám sát các tiến trình và network events liên quan đến **mshta.exe với tham số `-Embedding`** kết hợp cùng network connection inbound trên cổng động (49152+) → dấu hiệu của **`sc.exe` thực hiện kết nối RPC/SMB** để quản lý dịch vụ từ xa.
Thông thường, khi `sc.exe` được dùng để **create/start/modify service trên máy khác**, nó sinh ra hoạt động tương tự pattern này.

## Technical Context

* **Nguồn dữ liệu**:

  * Elastic Defend (EDR)
  * Sysmon
  * Windows Event Logs

* **Index patterns**:

  * `winlogbeat-*`
  * `logs-endpoint.events.process-*`
  * `logs-endpoint.events.network-*`
  * `logs-windows.sysmon_operational-*`

* **Logic rule (EQL)**:

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

  * `mshta.exe -Embedding` → thường thấy khi được **COM object gọi gián tiếp** (ở đây là SC Manager gọi RPC).
  * Kết hợp network connection inbound từ remote host → dấu hiệu **quản lý service từ xa qua sc.exe**.
  * Đây là pattern attacker lợi dụng cho lateral movement: copy payload lên máy đích → tạo service từ xa → khởi chạy service.

* **Ví dụ tấn công**:

  ```cmd
  sc.exe \\TARGETHOST create evilsvc binPath= "C:\Temp\payload.exe"
  sc.exe \\TARGETHOST start evilsvc
  ```

## Blind Spots and Assumptions

* Rule dựa vào `mshta.exe -Embedding`, có thể **không phát hiện nếu attacker dùng công cụ khác** (WMI, PsExec, PowerShell Remoting, DLL injection vào SCM API).
* Nếu admin hợp pháp hay phần mềm quản lý (SCCM, monitoring tools) dùng `sc.exe` để deploy/maintain service → sẽ sinh nhiều false positive.

## False Positives

* Quản trị viên cài đặt phần mềm hoặc update service qua domain script.
* Các tool IT hợp pháp: SCCM, Tanium, SolarWinds có thể trigger hành vi tương tự.
  👉 Cần baseline các host/ứng dụng hợp lệ và loại trừ chúng.

## Validation

1. Trên máy A, chạy:

   ```cmd
   sc.exe \\MAYB create testsvc binPath= "cmd.exe /c whoami > C:\temp\poc.txt"
   sc.exe \\MAYB start testsvc
   ```
2. Trên SIEM kiểm tra event `mshta.exe -Embedding` và network connection inbound trên cổng động.
3. Xác nhận rule bắn cảnh báo.

## Priority

* **Low (21)** mặc định vì hành vi này có thể là hợp pháp.
* **Medium/High** nếu phát hiện trên **máy không nằm trong nhóm quản trị** hoặc với **account có đặc quyền bất thường**.

## Response

1. Xác định **người dùng** đã chạy `sc.exe` và host nguồn.
2. Kiểm tra **service được tạo/thay đổi** (tên, đường dẫn binary).
3. Xác định service đó có thực thi payload lạ không.
4. Nếu nghi ngờ:

   * Stop & xóa service độc hại.
   * Kiểm tra lateral movement khác từ cùng account.
   * Reset credential liên quan.

## Additional Resources

* [Microsoft Docs – SC.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create)
* MITRE ATT\&CK: [T1021 – Remote Services](https://attack.mitre.org/techniques/T1021/)
* Elastic Rule Reference: [Service Command Lateral Movement](https://www.elastic.co/guide/en/security/current/prebuilt-rules-reference.html)

---

