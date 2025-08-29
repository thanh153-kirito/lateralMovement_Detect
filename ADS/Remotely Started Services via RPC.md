
---

# Remotely Started Services via RPC

## Goal

Phát hiện hành vi **khởi động dịch vụ Windows từ xa thông qua RPC (Remote Procedure Call)**.

* Đây là một kỹ thuật phổ biến để attacker thực thi lệnh từ xa (lateral movement).
* Nếu `services.exe` nhận kết nối RPC từ ngoài rồi spawn process mới, khả năng cao là một dịch vụ vừa bị khởi động từ xa.

---

## Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)** → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)

---

## Strategy Abstract

Trong Windows:

* `services.exe` quản lý toàn bộ dịch vụ hệ thống.
* Khi dịch vụ được start từ xa qua RPC, ta sẽ thấy **2 dấu hiệu kết hợp**:

  1. `services.exe` có **network connection RPC (TCP dynamic port ≥ 49152, incoming)**.
  2. `services.exe` spawn một process mới (ứng dụng dịch vụ).

Rule này tạo một **EQL sequence** để bắt chuỗi hành vi trên trong **1 giây**.
Nếu process mới không nằm trong danh sách loại trừ (IT agents, Veeam, ESET, SCCM, PDQ, TrustedInstaller, v.v.), khả năng cao đây là hành vi lateral movement.

---

## Technical Context

* **Nguồn dữ liệu**:

  * Elastic Defend
  * Sysmon
  * Windows Event Logs

* **Index patterns**:

  * `logs-endpoint.events.process-*`
  * `logs-endpoint.events.network-*`
  * `winlogbeat-*`
  * `logs-windows.sysmon_operational-*`

* **Logic Rule (EQL)**:

  ```eql
  sequence with maxspan=1s
     [network where host.os.type == "windows" and process.name : "services.exe" and
        network.direction : ("incoming", "ingress") and network.transport == "tcp" and
        source.port >= 49152 and destination.port >= 49152 and source.ip != "127.0.0.1" and source.ip != "::1"
     ] by host.id, process.entity_id
     [process where host.os.type == "windows" and 
         event.type == "start" and process.parent.name : "services.exe" and
         not (process.executable : "?:\\Windows\\System32\\msiexec.exe" and process.args : "/V") and
         not process.executable : (
                  "?:\\Pella Corporation\\*\\*.exe",
                  "?:\\Program Files (x86)\\*.exe",
                  "?:\\Program Files\\*.exe",
                  "?:\\Windows\\ADCR_Agent\\adcrsvc.exe",
                  "?:\\Windows\\AdminArsenal\\PDQ*.exe",
                  "?:\\Windows\\CAInvokerService.exe",
                  "?:\\Windows\\ccmsetup\\ccmsetup.exe",
                  "?:\\Windows\\eset-remote-install-service.exe",
                  "?:\\Windows\\ProPatches\\Scheduler\\STSchedEx.exe",
                  "?:\\Windows\\PSEXESVC.EXE",
                  "?:\\Windows\\RemoteAuditService.exe",
                  "?:\\Windows\\servicing\\TrustedInstaller.exe",
                  "?:\\Windows\\System32\\certsrv.exe",
                  "?:\\Windows\\System32\\sppsvc.exe",
                  "?:\\Windows\\System32\\srmhost.exe",
                  "?:\\Windows\\System32\\svchost.exe",
                  "?:\\Windows\\System32\\taskhostex.exe",
                  "?:\\Windows\\System32\\upfc.exe",
                  "?:\\Windows\\System32\\vds.exe",
                  "?:\\Windows\\System32\\VSSVC.exe",
                  "?:\\Windows\\System32\\wbem\\WmiApSrv.exe",
                  "?:\\Windows\\SysWOW64\\NwxExeSvc\\NwxExeSvc.exe",
                  "?:\\Windows\\Veeam\\Backup\\VeeamDeploymentSvc.exe",
                  "?:\\Windows\\VeeamLogShipper\\VeeamLogShipper.exe",
                  "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe"
         )] by host.id, process.parent.entity_id
  ```

* **Ý nghĩa kỹ thuật**:

  * Ràng buộc rất chặt: `services.exe` có connection RPC + spawn child process.
  * Loại trừ service hợp pháp từ vendor bảo mật & quản trị.
  * Alert sẽ xuất hiện khi một dịch vụ **không thường xuyên** được start từ xa.

---

## Blind Spots and Assumptions

* Nếu attacker **inject code trực tiếp vào service đã chạy**, rule sẽ không bắt được.
* Một số môi trường enterprise dùng **SCCM, PDQ Deploy, ADCR, Veeam** sẽ tạo nhiều FP nếu chưa baseline kỹ.
* Rule chỉ phát hiện RPC trên port ≥ 49152 (dynamic RPC). Nếu attacker dùng tunneling hoặc SMB pipe custom, có thể bypass.

---

## False Positives

* Admin hợp pháp khởi động dịch vụ từ xa qua PDQ, SCCM, Group Policy.
* Agent bảo mật/backup tự động bật dịch vụ qua RPC.
  👉 Cần baseline danh sách phần mềm IT được dùng trong môi trường.

---

## Validation

1. Từ máy attacker hoặc admin:

   ```cmd
   sc \\victim start <ServiceName>
   ```
2. Trên máy victim:

   * `services.exe` nhận connection RPC từ IP máy attacker.
   * `services.exe` spawn process (service).
   * Rule phải alert.

---

## Priority

* **Medium (47)**:

  * Đây là kỹ thuật lateral movement **phổ biến** (tương tự PsExec, Service Install).
  * Nhưng cũng **rất hay được dùng bởi admin hợp pháp** → cần phân tích ngữ cảnh.

---

## Response

1. Xác định service nào vừa được start và process binary path.
2. Kiểm tra source IP → có phải server quản trị hợp pháp hay host lạ?
3. Nếu dịch vụ bất thường → cô lập máy và phân tích binary.
4. Tìm thêm dấu hiệu lateral movement khác: file copy, account reuse, service creation.

---

## Additional Resources

* [MITRE ATT\&CK – T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)
* Microsoft Docs – [services.exe process details](https://learn.microsoft.com/en-us/windows/win32/services/services)
* Event ID 7040/7045 – Service changes & installations

---
