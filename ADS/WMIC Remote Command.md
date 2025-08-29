

---

# 🛡️ WMIC Remote Command

## 🎯 Goal

Phát hiện hành vi sử dụng **wmic.exe** với tham số `/node:` để thực thi lệnh trên **máy tính từ xa**. Đây có thể là hành động quản trị hợp pháp, nhưng attacker thường lạm dụng để thực hiện **lateral movement** hoặc **remote execution**.

---

## 🧩 Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)** → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
  * **Execution (TA0002)** → [Windows Management Instrumentation (T1047)](https://attack.mitre.org/techniques/T1047/)

---

## 📖 Strategy Abstract

* WMIC cho phép thực thi lệnh từ xa bằng cách sử dụng tùy chọn **`/node:<target>`**.
* Rule này tìm kiếm:

  * **process.name** = `wmic.exe`
  * **process.args** có `/node:<IP hoặc hostname>`
  * Kèm theo các action thường dùng: `call`, `set`, `get`
* **Loại trừ (whitelist):** khi `/node` trỏ về `localhost` hoặc `127.0.0.1`, vì đây chỉ là lệnh chạy cục bộ.

---

## ⚙️ Technical Context

* **Nguồn dữ liệu**:

  * Sysmon (Process Create Event)
  * Windows Security Event Logs
  * Elastic Defend / Endgame
* **Ví dụ command bị bắt:**

  ```bash
  wmic /node:192.168.1.10 process call create "cmd.exe /c whoami"
  wmic /node:Target-PC path win32_service get name,startmode
  ```
* **Query EQL:**

  ```eql
  process where host.os.type == "windows" and event.type == "start" and
    process.name : "WMIC.exe" and
    process.args : "*node:*" and
    process.args : ("call", "set", "get") and
    not process.args : ("*/node:localhost*", "*/node:\"127.0.0.1\"*", "/node:127.0.0.1")
  ```

---

## 🚧 Blind Spots and Assumptions

* Không phát hiện nếu attacker:

  * Dùng **PowerShell** hoặc **CIM cmdlets** để gọi WMI từ xa thay vì wmic.exe.
  * Sử dụng COM/DCOM trực tiếp để gọi WMI mà không qua binary wmic.exe.
* Rule chỉ kiểm tra `/node:` → attacker có thể dùng tool tùy chỉnh hoặc script WMI API.

---

## ⚠️ False Positives

* Quản trị viên sử dụng WMIC để:

  * Kiểm tra service từ xa
  * Triển khai / cấu hình phần mềm
* Có thể gây noise trong môi trường IT có thói quen dùng WMIC.
  👉 Giải pháp: Whitelist người dùng/admin account hoặc subnet quản trị hợp pháp.

---

## 🧪 Validation

1. Từ máy A chạy:

   ```bash
   wmic /node:192.168.1.20 process call create "calc.exe"
   ```
2. Kiểm tra log trên SIEM → Rule phải trigger với **process.name=wmic.exe** và **args chứa `/node:192.168.1.20`**.

---

## 🛡️ Priority

* **Low (21)** theo mặc định.
* Có thể nâng lên **Medium/High** nếu trong doanh nghiệp không có lý do hợp pháp để dùng WMIC remote.
* Lưu ý: WMIC đã bị Microsoft deprecate, nên hầu hết trường hợp hiện tại nếu còn xuất hiện là đáng nghi.

---

## 🚨 Response

1. Xác định **tài khoản người dùng** chạy WMIC.
2. Kiểm tra **host đích** bị gọi từ xa để xem có tiến trình bất thường.
3. Thu thập command line đầy đủ (`process.args`) để phân tích ý đồ.
4. Nếu là tấn công → cô lập endpoint, reset credential liên quan, hunting các hoạt động lateral movement khác (SMB, Scheduled Task, WinRM…).

---

## 📚 Additional Resources

* [MITRE ATT\&CK – T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
* Microsoft Docs: [Deprecation of WMIC](https://learn.microsoft.com/en-us/windows/deprecate-wmic)

---

