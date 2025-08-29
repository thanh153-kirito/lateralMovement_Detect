

---

# At.exe Command Lateral Movement

## Goal

Phát hiện hành vi sử dụng **at.exe** để tương tác với **Task Scheduler trên máy từ xa** (remote host). Điều này thường được attacker lợi dụng để thực thi lệnh từ xa hoặc tạo persistence, mặc dù trong hệ thống hiện đại `at.exe` đã bị **deprecated** (thay bằng `schtasks.exe`).

---

## Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)** → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
  * **Execution (TA0002)** → [Scheduled Task/Job (T1053)](https://attack.mitre.org/techniques/T1053/)

---

## Strategy Abstract

* `at.exe` là công cụ dòng lệnh được dùng để:

  * Tạo task theo lịch.
  * Chạy chương trình hoặc script vào thời gian định sẵn.
  * Chạy task trên **remote host** nếu sử dụng cú pháp `\\<remote_host>`.
* Attacker có thể lạm dụng `at.exe` để:

  * Thực thi command từ xa trên máy trong cùng domain/network.
  * Cài persistence bằng việc tạo scheduled task độc hại.
* Rule phát hiện khi có process:

  * **Name**: `at.exe`
  * **Args**: `\\*` → chỉ ra việc tác động tới máy tính từ xa.

---

## Technical Context

* **Nguồn dữ liệu**:

  * Elastic Endgame
  * Elastic Defend
  * Windows Security Event Logs
* **Index Patterns**:

  * `endgame-*`
  * `logs-endpoint.events.process-*`
  * `logs-system.security*`
  * `logs-windows.*`
  * `winlogbeat-*`
* **Logic Rule (EQL)**:

  ```eql
    process where host.os.type == "windows" and event.type == "start" and process.name : "at.exe" and process.args : "\\\\*"
  ```

---

## Blind Spots and Assumptions

* Không phát hiện khi attacker dùng **schtasks.exe**, PowerShell (`New-ScheduledTask`), hoặc WMI để tạo task remote.
* `at.exe` bị **deprecated từ Windows 8/Windows Server 2012** → nếu môi trường toàn Windows mới → rule ít tác dụng.
* Giả định rằng mọi hoạt động `at.exe` remote là đáng ngờ, nhưng trong môi trường cũ vẫn có thể hợp pháp.

---

## False Positives

* Quản trị viên IT trong hệ thống legacy có thể vẫn sử dụng `at.exe` để quản lý job từ xa.
* Một số script cũ (batch/automation) có thể còn chứa lệnh `at \\remotehost`.
  👉 Nên lọc whitelist theo tài khoản admin và host hợp pháp.

---

## Validation

1. Trên máy A, chạy lệnh thử:

   ```cmd
   at \\MACHINE_B 13:00 cmd.exe /c calc.exe
   ```
2. Quan sát log trên máy A:

   * Process creation: `at.exe \\MACHINE_B ...`
3. Rule trigger với process name = `at.exe`, args chứa `\\MACHINE_B`.

---

## Priority

* **Low (21)** – vì:

  * Công cụ đã cũ và ít được dùng trên hệ thống hiện đại.
  * Có khả năng FP cao nếu môi trường legacy còn dùng at.exe thật.
  * Tuy nhiên, nếu phát hiện trong môi trường mới → cần điều tra ngay (vì chắc chắn bất thường).

---

## Response

1. Xác định **người dùng / tài khoản** nào đã chạy `at.exe`.
2. Kiểm tra host đích trong args `\\<remote>` để xem task nào được tạo.
3. Review Windows Task Scheduler logs trên remote host (`Microsoft-Windows-TaskScheduler/Operational`).
4. Nếu task khả nghi → xóa task, điều tra nguồn gốc lệnh, reset credentials bị lạm dụng.
5. Correlate với các rule khác liên quan scheduled tasks hoặc lateral movement (`schtasks.exe`, `Remote Scheduled Task Creation`).

---

## Additional Resources

* [MITRE ATT\&CK – T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
* [Microsoft Docs – AT command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at) (deprecated)

---

