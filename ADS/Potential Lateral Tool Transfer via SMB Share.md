

---

# 🛡️ Potential Lateral Tool Transfer via SMB Share

## 🎯 Goal

Phát hiện hành vi khả nghi khi **tập tin thực thi (EXE/DLL/COM/…)** được tạo hoặc chỉnh sửa qua **SMB share (port 445)**. Đây thường là bước attacker **copy công cụ / malware / payload** sang máy nạn nhân để chuẩn bị cho **lateral movement hoặc execution**.

---

## 🧩 Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)**

    * [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
    * [Lateral Tool Transfer (T1570)](https://attack.mitre.org/techniques/T1570/)

---

## 📖 Strategy Abstract

Rule này tìm chuỗi sự kiện trong vòng **30 giây**:

1. **SMB inbound connection (port 445)**

   * Process: `System (PID 4)` nhận kết nối TCP inbound.
   * Điều kiện: `incoming / ingress` traffic, không phải loopback.

2. **File creation/change (executable)**

   * Cũng bởi `System (PID 4)` → dấu hiệu file được tạo từ kernel/network driver thay vì một process user-space.
   * File có header MZ (`4d5a`) hoặc extension: `.exe`, `.scr`, `.pif`, `.com`, `.dll`.

👉 Sự kết hợp này = **một executable được copy qua SMB share vào host**.

---

## ⚙️ Technical Context

* **Nguồn dữ liệu:**

  * Endpoint + file events (Elastic Defend, Sysmon, Defender ATP, …)
  * Network events (port 445 inbound, handled by PID 4)

* **Ví dụ IOC:**

  ```none
  network: System (PID 4) inbound TCP 445 from 10.1.2.5
  file: C:\Users\Public\Tools\procdump64.exe created by PID 4
  ```

* **Query logic:**

  ```eql
  sequence by host.id with maxspan=30s
  [network where host.os.type == "windows" and event.type == "start" and process.pid == 4 and destination.port == 445 and
   network.direction : ("incoming", "ingress") and
   network.transport == "tcp" and source.ip != "127.0.0.1" and source.ip != "::1"
  ] by process.entity_id
  /* add more executable extensions here if they are not noisy in your environment */
  [file where host.os.type == "windows" and event.type in ("creation", "change") and process.pid == 4 and 
   (file.Ext.header_bytes : "4d5a*" or file.extension : ("exe", "scr", "pif", "com", "dll"))] by process.entity_id
  ```

---

## 🚧 Blind Spots and Assumptions

* Rule không detect nếu attacker:

  * Copy file qua **RDP clipboard**, **HTTP**, **WinRM**, hoặc **cloud storage**.
  * Rename file sang extension khác (e.g., `.txt`) rồi đổi lại sau.
* SMB traffic nội bộ phục vụ **patching** hoặc **software deployment** cũng có thể trigger (→ cần whitelist).

---

## ⚠️ False Positives

* **Hệ thống quản lý bản vá, update, deployment** (PDQ Deploy, SCCM, Intune, antivirus distribution…).
* **IT admin** copy tool hợp pháp qua SMB share (e.g., procdump.exe để debug).

👉 Tuy nhiên, đa số môi trường **hiện đại** không còn phụ thuộc vào SMB để distribute EXE trực tiếp → nên bất kỳ detection nào đều đáng điều tra.

---

## 🧪 Validation

1. Dùng `net use` để map SMB share:

   ```powershell
   net use \\victim\C$
   copy mimikatz.exe \\victim\C$\Users\Public\
   ```
2. Quan sát SIEM:

   * `System (PID 4)` nhận inbound SMB.
   * File `mimikatz.exe` được tạo qua PID 4.

Rule phải trigger. ✅

---

## 🛡️ Priority

* **Severity:** Medium (47)
* Đánh giá lại theo môi trường:

  * Nếu SMB lateral movement không được cho phép → nâng lên **High**.
  * Nếu nhiều deployment tool dựa vào SMB → giữ Medium nhưng cần **tuning** kỹ whitelist.

---

## 🚨 Response

1. Điều tra **nguồn IP** tạo SMB connection.
2. Kiểm tra **file được copy**: hash, path, signature.
3. Nếu file là công cụ hacking / không được phép:

   * Cách ly host nhận file.
   * Chặn SMB traffic từ IP nguồn.
   * Threat hunting để phát hiện **execution step** (process spawn từ file mới).

---

## 📚 Additional Resources

* [MITRE ATT\&CK – Lateral Tool Transfer (T1570)](https://attack.mitre.org/techniques/T1570/)
* [Elastic Detection Rule – Lateral Tool Transfer](https://github.com/elastic/detection-rules)
* Red Team TTPs: Copying mimikatz.exe, psexec.exe qua `\\C$\` shares.

---

