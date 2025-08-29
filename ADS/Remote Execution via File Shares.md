
---

# Remote Execution via File Shares

## 🎯 Goal

Phát hiện việc **thực thi file thực thi (EXE)** được tạo bởi **tiến trình hệ thống (PID = 4, System process)**, thường xảy ra khi attacker copy malware qua **SMB file share** (\ADMIN\$, \C\$, …) và sau đó chạy nó từ máy đích để thực hiện lateral movement.

---

## 🧩 Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)** → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)

---

## 📖 Strategy Abstract

* Khi file được tạo bởi **System process (PID 4)** → thường là kết quả của **SMB file copy từ host khác**.
* Nếu sau đó file này được **thực thi**, đó là dấu hiệu khả nghi của lateral movement.
* Rule này hoạt động theo logic **sequence**:

  1. **Bước 1:** File `.exe` (hoặc header `MZ 4D5A*`) được tạo bởi PID=4 (quá trình hệ thống, đại diện cho SMB/Network I/O).
  2. **Bước 2:** File vừa tạo được thực thi (`event.type: start`).
* Rule có **whitelist** để tránh FP từ:

  * Veeam backup
  * PDQ Deploy/Inventory
  * CrowdStrike sensor
  * Microsoft ccmsetup
  * CyberArk InvokerService
  * Sophos Update
  * Elastic Agent

---

## ⚙️ Technical Context

* **Nguồn dữ liệu**:

  * Endpoint Security Logs (Elastic Defend, Endgame)
  * Process + File creation events

* **Query EQL (tóm tắt)**:

  ```eql
    sequence with maxspan=1m
  [file where host.os.type == "windows" and event.type in ("creation", "change") and 
   process.pid == 4 and (file.extension : "exe" or file.Ext.header_bytes : "4d5a*")] by host.id, file.path
  [process where host.os.type == "windows" and event.type == "start" and
    not (
      /* Veeam related processes */
      (
        process.name : (
          "VeeamGuestHelper.exe", "VeeamGuestIndexer.exe", "VeeamAgent.exe", "VeeamLogShipper.exe",
          "Veeam.VSS.Sharepoint20??.exe", "OracleProxy.exe", "Veeam.SQL.Service", "VeeamDeploymentSvc.exe"
        ) and process.code_signature.trusted == true and process.code_signature.subject_name : "Veeam Software Group GmbH"
      ) or
      /* PDQ related processes */
      (
        process.name : (
          "PDQInventoryScanner.exe", "PDQInventoryMonitor.exe", "PDQInventory-Scanner-?.exe",
          "PDQInventoryWakeCommand-?.exe", "PDQDeployRunner-?.exe"
        ) and process.code_signature.trusted == true and process.code_signature.subject_name : "PDQ.com Corporation"
      ) or
      /* CrowdStrike related processes */
      (
        (process.executable : "?:\\Windows\\System32\\drivers\\CrowdStrike\\*Sensor*.exe" and 
         process.code_signature.trusted == true and process.code_signature.subject_name : "CrowdStrike, Inc.") or
        (process.executable : "?:\\Windows\\System32\\drivers\\CrowdStrike\\*-CsInstallerService.exe" and 
         process.code_signature.trusted == true and process.code_signature.subject_name : "Microsoft Windows Hardware Compatibility Publisher")
      ) or
      /* MS related processes */
      (
        process.executable == "System" or
        (process.executable : "?:\\Windows\\ccmsetup\\ccmsetup.exe" and 
         process.code_signature.trusted == true and process.code_signature.subject_name : "Microsoft Corporation")
      ) or
      /* CyberArk processes */
      (
        process.executable : "?:\\Windows\\CAInvokerService.exe" and 
        process.code_signature.trusted == true and process.code_signature.subject_name : "CyberArk Software Ltd."
      )  or
      /* Sophos processes */
      (
        process.executable : "?:\\ProgramData\\Sophos\\AutoUpdate\\Cache\\sophos_autoupdate1.dir\\SophosUpdate.exe" and 
        process.code_signature.trusted == true and process.code_signature.subject_name : "Sophos Ltd"
      )  or
      /* Elastic processes */
      (
        process.executable : (
          "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\previous\\elastic-endpoint.exe",
          "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\elastic-agent.exe",
          "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\agentbeat.exe"
        ) and 
        process.code_signature.trusted == true and process.code_signature.subject_name : "Elasticsearch, Inc."
      ) 
    )
  ] by host.id, process.executable
  ```

---

## 🚧 Blind Spots and Assumptions

* Không phát hiện nếu attacker:

  * Copy file qua **RDP clipboard**, **WMI**, hoặc kỹ thuật khác không dùng SMB.
  * Rename file thành định dạng khác (dll, scr, com) rồi thực thi.
* Phụ thuộc vào việc endpoint có log **file creation + process start** đầy đủ.

---

## ⚠️ False Positives

* Có thể xảy ra nếu các phần mềm quản trị / triển khai hợp pháp (không nằm trong whitelist) copy và chạy file qua SMB.
* Ví dụ: Script admin tự động đẩy EXE qua share và chạy từ xa.

👉 Giải pháp: Whitelist thêm các ứng dụng/quy trình triển khai hợp pháp tại doanh nghiệp.

---

## 🧪 Validation

1. Từ một máy A, copy file test.exe vào máy B qua `\\<target>\C$\Windows\Temp\test.exe`.
2. Trên máy B, chạy file đó.
3. Log sẽ ghi nhận:

   * File `test.exe` được tạo bởi `System (PID 4)`.
   * Sau đó process `test.exe` được start.
4. Rule sẽ trigger.

---

## 🛡️ Priority

* **Medium (47)**

  * Do có thể có false positives từ các phần mềm triển khai IT hợp pháp.
  * Nhưng nếu môi trường không có PDQ, Veeam, hay tool deployment hợp pháp → mức độ nghiêm trọng **cao**, vì khả năng là lateral movement thực sự.

---

## 🚨 Response

1. Xác định **máy nguồn** đã copy file vào share.
2. Kiểm tra **người dùng** đã thực hiện hành động.
3. Phân tích file thực thi: hash, signature, liên hệ với threat intel.
4. Kiểm tra các host khác xem có hoạt động SMB tương tự.
5. Nếu xác nhận là tấn công → cách ly host, chặn SMB connection từ nguồn, reset credential liên quan.

---

## 📚 Additional Resources

* [MITRE ATT\&CK – T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)
* Elastic Security Docs: [Remote Execution detection](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)

---

