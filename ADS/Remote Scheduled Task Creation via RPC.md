
---

# Remote Scheduled Task Creation via RPC

## Goal

Phát hiện hành vi **tạo Scheduled Task từ xa thông qua RPC**.

* Kỹ thuật này thường được attacker dùng để thực thi lệnh trên máy nạn nhân một cách **bền vững** và **khó phát hiện**.
* Nó có thể đóng vai trò trong **lateral movement** hoặc **persistence**.

---

## Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)** → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
  * **Execution (TA0002)** → [Scheduled Task/Job (T1053)](https://attack.mitre.org/techniques/T1053/)

---

## Strategy Abstract

* Trên Windows, Scheduled Tasks có thể được quản lý từ xa qua **RPC calls**.
* Nếu một task mới được tạo từ client RPC từ xa, Windows Security Logs sẽ ghi lại event với thông tin:

  * `event.action == "scheduled-task-created"`
  * `RpcCallClientLocality : "0"` → nghĩa là call đến từ remote (không phải local).
  * `ClientProcessId : "0"` → RPC request, không có PID cục bộ.

Rule sẽ bắt chính xác trường hợp này để chỉ ra một Scheduled Task được **khởi tạo từ máy khác**.

---

## Technical Context

* **Nguồn dữ liệu**:

  * Windows Security Event Logs

* **Index patterns**:

  * `logs-system.security*`
  * `logs-windows.forwarded*`
  * `winlogbeat-*`

* **Logic Rule (EQL)**:

  ```eql
  iam where event.action == "scheduled-task-created" and
   winlog.event_data.RpcCallClientLocality : "0" and 
   winlog.event_data.ClientProcessId : "0"
  ```

* **Ý nghĩa kỹ thuật**:

  * Rule dựa hoàn toàn vào **event log fields** của Windows.
  * Điều kiện `RpcCallClientLocality: 0` lọc ra những event được tạo qua **RPC từ xa**.
  * `ClientProcessId: 0` chỉ ra request không được spawn từ một process local mà đến từ remote call.

---

## Blind Spots and Assumptions

* Nếu attacker tạo task trực tiếp qua `schtasks.exe` trên máy nạn nhân, rule này sẽ không phát hiện (chỉ phát hiện remote RPC).
* Một số công cụ quản trị hệ thống (SCCM, PDQ, Group Policy Preferences) có thể dùng cơ chế này để tạo task → gây **false positive**.
* Rule giả định rằng trường `RpcCallClientLocality` và `ClientProcessId` luôn log chính xác (có thể khác nhau giữa các phiên bản Windows).

---

## False Positives

* Admin hợp pháp hoặc tool IT (PDQ, SCCM, GPO) tạo scheduled tasks từ xa.
* Một số phần mềm quản lý endpoint (EDR, patch management) có thể tạo task bằng RPC để deploy agent.
  👉 Cần baseline: danh sách các scheduled task hợp pháp được deploy trong môi trường.

---

## Validation

1. Từ một máy quản trị, chạy:

   ```cmd
   schtasks /create /s <RemoteHost> /u <Domain\User> /p <Password> /sc once /tn "TestRemoteTask" /tr "cmd.exe /c calc.exe"
   ```
2. Trên máy mục tiêu, kiểm tra Security Event Logs → sẽ thấy event với `scheduled-task-created` + RPC fields.
3. Rule sẽ bắn alert.

---

## Priority

* **Medium (47)**

  * Đây là một kỹ thuật lateral movement thực tế (dùng `schtasks /create /s` hoặc qua RPC API).
  * Nhưng cũng có **nhiều false positive** từ hoạt động quản trị hợp pháp.
  * Cần correlation với **user account + remote source IP** để nâng độ tin cậy.

---

## Response

1. Kiểm tra tên và command của Scheduled Task mới tạo.
2. Xác định source IP hoặc user account tạo task từ xa.
3. Nếu không khớp với IT admin hợp pháp → điều tra escalation/lateral movement.
4. Xem thêm các hành vi liên quan:

   * File copy từ xa
   * Service creation/start
   * PsExec hoặc WMI execution

---

## Additional Resources

* [MITRE ATT\&CK – T1053 Scheduled Task](https://attack.mitre.org/techniques/T1053/)
* Microsoft Docs – [schtasks.exe command-line reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
* Event ID 4698 – Scheduled Task created

---

