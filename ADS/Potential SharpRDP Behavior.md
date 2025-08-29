
---

# 🛡️ Potential SharpRDP Behavior

## 🎯 Goal

Phát hiện hành vi đáng ngờ liên quan đến **SharpRDP** – một công cụ cho phép thực thi lệnh từ xa qua **Remote Desktop Protocol (RDP)** sau khi xác thực thành công, từ đó hỗ trợ attacker **lateral movement** trong hệ thống.

---

## 🧩 Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)** → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)

---

## 📖 Strategy Abstract

Rule này phát hiện chuỗi sự kiện đặc trưng cho SharpRDP:

1. **Incoming RDP connection**

   * `svchost.exe` lắng nghe port `3389` (RDP default).
2. **Registry modification (RunMRU key)**

   * `explorer.exe` ghi giá trị mới trong:

     ```
     HKEY_USERS\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\
     ```
   * Chuỗi giá trị là lệnh đáng ngờ: `cmd.exe`, `powershell.exe`, `taskmgr`, hoặc thực thi từ `\\tsclient\` (share của RDP).
3. **Process execution**

   * Tiến trình được spawn từ `cmd.exe`, `powershell.exe`, `taskmgr.exe` hoặc chạy binary từ `\\tsclient\`.
   * Ngoại trừ `conhost.exe` (tiến trình console hợp pháp).

👉 Đây là “behavior chain” khá đặc thù của **SharpRDP**, khi nó inject lệnh vào session explorer của nạn nhân để chạy ngay sau khi kết nối RDP.

---

## ⚙️ Technical Context

* **Nguồn dữ liệu:**

  * Endpoint logs (Elastic Defend, Sysmon, Defender, …)
  * Process creation, registry modification, network activity
* **Ví dụ dấu hiệu:**

  ```none
  network: svchost.exe -> 3389 (incoming RDP)
  registry: RunMRU key updated with "powershell.exe -nop -w hidden ..."
  process: powershell.exe spawns with suspicious arguments
  ```
* **Query logic:**

  ```eql
  /* Incoming RDP followed by a new RunMRU string value set to cmd, powershell, taskmgr or tsclient, followed by process execution within 1m */

  sequence by host.id with maxspan=1m
    [network where host.os.type == "windows" and event.type == "start" and process.name : "svchost.exe" and destination.port == 3389 and
    network.direction : ("incoming", "ingress") and network.transport == "tcp" and
    source.ip != "127.0.0.1" and source.ip != "::1"
    ]

    [registry where host.os.type == "windows" and event.type == "change" and process.name : "explorer.exe" and
    registry.path : ("HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\*") and
    registry.data.strings : ("cmd.exe*", "powershell.exe*", "taskmgr*", "\\\\tsclient\\*.exe\\*")
    ]

    [process where host.os.type == "windows" and event.type == "start" and
    (process.parent.name : ("cmd.exe", "powershell.exe", "taskmgr.exe") or process.args : ("\\\\tsclient\\*.exe")) and
    not process.name : "conhost.exe"
    ]
  ```

---

## 🚧 Blind Spots and Assumptions

* Không phát hiện nếu attacker không để lại RunMRU key (ví dụ, RDP manual input khác).
* Nếu attacker dùng RDP kết hợp với **clipboard injection** hoặc kỹ thuật khác → không match rule.
* Nếu SharpRDP được fork/obfuscate để thay đổi hành vi (không dùng RunMRU).

---

## ⚠️ False Positives

* Người dùng thực sự mở **cmd.exe** hoặc **powershell.exe** từ Run prompt (`Win+R`) sau khi RDP vào.
* Các ứng dụng hợp pháp ghi giá trị vào **RunMRU**.
  👉 Tuy nhiên, chuỗi sự kiện 3 bước liên tiếp trong vòng **1 phút** rất hiếm khi là hợp pháp → **độ tin cậy cao**.

---

## 🧪 Validation

1. Dùng SharpRDP hoặc mô phỏng thủ công:

   * RDP vào máy từ xa.
   * Mở `Win+R` → nhập `cmd.exe` hoặc `powershell.exe`.
   * Chạy thử `whoami` hoặc `calc.exe`.
2. Kiểm tra log trong SIEM → Rule phải trigger đúng chuỗi: RDP → RunMRU → Process execution.

---

## 🛡️ Priority

* **High (73)** theo mặc định → hợp lý vì đây gần như luôn là malicious lateral movement.
* Có thể set thành **Critical** nếu trong tổ chức:

  * Không cho phép RDP inbound từ user → server.
  * Có chính sách nghiêm ngặt về remote admin.

---

## 🚨 Response

1. Xác định **nguồn IP** mở RDP connection.
2. Kiểm tra tài khoản user → có phải admin hợp pháp?
3. Điều tra process được thực thi (cmd, powershell, tsclient binary).
4. Nếu là tấn công:

   * Ngắt RDP session, isolate host.
   * Reset credential liên quan.
   * Hunting lateral movement khác (scheduled task, SMB, WinRM, WMI…).

---

## 📚 Additional Resources

* [MITRE ATT\&CK – Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
* SharpRDP GitHub project (phân tích red team tool).
* [Elastic Detection Rule for SharpRDP](https://github.com/elastic/detection-rules).

---
