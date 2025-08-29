

---

# Remote Windows Service Installed

## Goal

Phát hiện hành vi **tạo dịch vụ Windows từ xa sau khi có network logon**. Đây là một trong những cách attacker thường dùng để thực thi code từ xa và duy trì quyền truy cập trong hệ thống.

* Kẻ tấn công thường dùng **sc.exe, PsExec, WMI, hoặc công cụ tùy chỉnh** để tạo service chạy mã độc trên host nạn nhân.
* Nếu thấy event **service-installed** ngay sau một **network logon** (cùng `LogonId`), nhiều khả năng đây là **lateral movement**.

---

## Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)** → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
  * **Persistence (TA0003)** → [Create or Modify System Process (T1543)](https://attack.mitre.org/techniques/T1543/)

---

## Strategy Abstract

Windows Service là một cơ chế hợp pháp để thực thi code với quyền cao (SYSTEM).

* Attacker có thể lợi dụng API **CreateService()** hoặc công cụ `sc.exe` để tạo dịch vụ mới trên máy từ xa sau khi đăng nhập qua SMB/Network Logon.
* Rule này kiểm tra **2 sự kiện liên tiếp (trong vòng 1 phút)**:

  1. **Authentication (Network Logon)** thành công từ IP khác.
  2. **Service Installation** với cùng `LogonId`.

→ Nếu có chuỗi hành vi này, nhiều khả năng attacker đang **triển khai payload từ xa**.

---

## Technical Context

* **Nguồn dữ liệu**: Windows Security Event Logs

* **Index patterns**:

  * `logs-system.security*`
  * `logs-windows.forwarded*`
  * `winlogbeat-*`

* **Logic Rule (EQL)**:

  ```eql
  sequence by winlog.logon.id, winlog.computer_name with maxspan=1m
    [authentication where event.action == "logged-in" and winlog.logon.type : "Network" and
     event.outcome=="success" and source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1"]
    [iam where event.action == "service-installed" and
     not winlog.event_data.SubjectLogonId : "0x3e7" and
     not winlog.event_data.ServiceFileName :
                   ("?:\\Windows\\ADCR_Agent\\adcrsvc.exe",
                    "?:\\Windows\\System32\\VSSVC.exe",
                    "?:\\Windows\\servicing\\TrustedInstaller.exe",
                    "?:\\Windows\\System32\\svchost.exe",
                    "?:\\Program Files (x86)\\*.exe",
                    "?:\\Program Files\\*.exe",
                    "?:\\Windows\\PSEXESVC.EXE",
                    "?:\\Windows\\System32\\sppsvc.exe",
                    "?:\\Windows\\System32\\wbem\\WmiApSrv.exe",
                    "?:\\WINDOWS\\RemoteAuditService.exe",
                    "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe",
                    "?:\\Windows\\VeeamLogShipper\\VeeamLogShipper.exe",
                    "?:\\Windows\\CAInvokerService.exe",
                    "?:\\Windows\\System32\\upfc.exe",
                    "?:\\Windows\\AdminArsenal\\PDQ*.exe",
                    "?:\\Windows\\System32\\vds.exe",
                    "?:\\Windows\\Veeam\\Backup\\VeeamDeploymentSvc.exe",
                    "?:\\Windows\\ProPatches\\Scheduler\\STSchedEx.exe",
                    "?:\\Windows\\System32\\certsrv.exe",
                    "?:\\Windows\\eset-remote-install-service.exe",
                    "?:\\Pella Corporation\\*\\*.exe",
                    "?:\\Windows\\SysWOW64\\NwxExeSvc\\NwxExeSvc.exe",
                    "?:\\Windows\\System32\\taskhostex.exe")]
  ```

* **Ý nghĩa kỹ thuật**:

  * Ghép 2 loại event: logon network → service creation.
  * Loại trừ các dịch vụ hợp pháp từ vendor IT/bảo mật (Veeam, ESET, PDQ, Pella, Cynet, v.v.).
  * Nếu thấy service lạ được cài sau network logon → khả năng cao là lateral movement.

---

## Blind Spots and Assumptions

* Nếu attacker dùng **dịch vụ có tên giống phần mềm hợp pháp** thì detection có thể bỏ sót.
* Không phát hiện nếu attacker **inject trực tiếp vào service hợp pháp** thay vì cài mới.
* Rule có thể noisy trong môi trường có nhiều **admin tools triển khai phần mềm qua service** (SCCM, PDQ Deploy).

---

## False Positives

* Admin hợp pháp triển khai dịch vụ mới từ xa.
* Công cụ IT hợp pháp (VD: PDQ, Veeam, ADCR agent, phần mềm backup/patch management).
  👉 Cần baseline và tạo allowlist thêm nếu có nhiều alert không quan trọng.

---

## Validation

1. Trên máy attacker:

   ```cmd
   sc \\victim create EvilService binPath= "C:\temp\evil.exe" start= auto
   sc \\victim start EvilService
   ```
2. Kiểm tra Windows Security Logs trên victim:

   * Event **4624 (Network Logon)**.
   * Event **7045 (Service Installed)**.
   * Rule phải alert nếu cùng LogonId.

---

## Priority

* **Medium (47)**:

  * Lateral movement qua service creation là kỹ thuật **nguy hiểm và phổ biến**.
  * Tuy nhiên có nhiều khả năng là hành vi admin hợp pháp → cần phân tích ngữ cảnh trước khi xử lý.

---

## Response

1. Xác minh service vừa được tạo (tên, đường dẫn file thực thi).
2. Nếu file/service không thuộc phần mềm hợp pháp → cô lập endpoint.
3. Kiểm tra source IP, user account đã thực hiện logon → có dấu hiệu credential theft?
4. Threat hunt trong toàn bộ môi trường: có service lạ khác được cài không?
5. Nếu xác định malicious → reset account, block IP, forensic binary.

---

## Additional Resources

* [MITRE ATT\&CK – T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)
* [MITRE ATT\&CK – T1543 Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
* Microsoft Docs – [Event ID 7045: A service was installed in the system](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-7045)

---


