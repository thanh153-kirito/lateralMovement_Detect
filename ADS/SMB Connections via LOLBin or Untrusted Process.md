
---

# 🛡️ SMB Connections via LOLBin or Untrusted Process

## 🎯 Goal

Phát hiện các tiến trình **không hợp lệ, không đáng tin cậy hoặc LOLBins** tạo kết nối **SMB (TCP/445)**. Trong Windows, kết nối SMB **hợp pháp** hầu hết được tạo bởi **kernel/System (PID 4)**, do đó các kết nối xuất phát từ **user-level process** thường là dấu hiệu của hành vi **quét SMB, khai thác, hoặc lateral movement**.

---

## 🧩 Categorization

* **MITRE ATT\&CK**

  * **Lateral Movement (TA0008)**

    * [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)

---

## 📖 Strategy Abstract

Rule thực hiện **sequence trong 1 phút**:

1. **Process khởi tạo (event.type = start)**

   * Không phải `PID 4` (System).
   * Không phải NT AUTHORITY hoặc Network Service (`S-1-5-19`, `S-1-5-20`).
   * Nếu **trusted & signed nhưng không phải của Microsoft** → bỏ qua.
   * Nếu là **PowerShell từ Defender ATP download folder** → bỏ qua (để giảm FP).

2. **Network connection qua SMB (TCP/445)**

   * Process PID khác 4.
   * Liên kết với process ở bước trên.

👉 Khi một **process user-level hoặc LOLBin** mở SMB connection → rule sẽ cảnh báo.

---

## ⚙️ Technical Context

* **LOLBin** có thể bị lạm dụng cho SMB lateral movement:

  * `rundll32.exe`
  * `wmic.exe`
  * `powershell.exe`
  * `certutil.exe`
  * `mshta.exe`

* Ngoài ra, **malware chưa được sign** hoặc tool pentest (Mimikatz, CrackMapExec agents) cũng có thể bị phát hiện.

* **Ví dụ log:**

  ```none
  process: rundll32.exe started by user:CORP\jdoe
  network: rundll32.exe → 10.10.5.23:445 (TCP)
  ```

---

## 🚧 Blind Spots and Assumptions

* Rule chỉ quan sát **port 445**, không cover các phương thức lateral movement khác như:

  * WebDAV (port 80/443).
  * RDP clipboard/file transfer.
  * WinRM (5985/5986).
* Nếu attacker đổi binary thành self-signed trusted binary với "Microsoft" trong subject name (edge-case) → có thể bypass.

---

## ⚠️ False Positives

* Một số ứng dụng hợp pháp non-Microsoft có thể kết nối SMB (ví dụ: client backup, monitoring tools) → nhưng rule đã **whitelist trusted signed non-MS** để giảm noise.
* Một số hoạt động quản trị/IT scripts chạy SMB copy bằng `powershell.exe` → có thể gây alert.

👉 Cần xây dựng **allowlist theo process name hoặc publisher** trong từng môi trường.

---

## 🧪 Validation

1. Chạy thử với `rundll32.exe`:

   ```cmd
   rundll32.exe setupapi,InstallHinfSection DefaultInstall 128 \\10.10.5.20\share\test.inf
   ```

   → Tạo kết nối SMB từ rundll32.

2. Chạy `wmic.exe /node:10.10.5.21 process list` → cũng trigger SMB.

3. Quan sát SIEM:

   * Process start (non PID 4).
   * Network event TCP/445 từ process đó.

Rule phải trigger. ✅

---

## 🛡️ Priority

* **Severity:** Medium (47)
* Tuy nhiên nếu môi trường không cho phép **user processes tạo SMB traffic** → có thể nâng thành **High** vì gần như chắc chắn là malicious.

---

## 🚨 Response

1. Điều tra **process** khởi tạo SMB:

   * Publisher, signature, command line.
   * Parent process (có thể là injection / LOLBin abuse).
2. Xác minh **IP đích**: là domain controller, file server hay endpoint khác?
3. Nếu process là bất thường:

   * Suspend hoặc kill process.
   * Block SMB session.
   * Kiểm tra lateral movement hoặc payload copy qua SMB.

---

## 📚 Additional Resources

* [MITRE ATT\&CK – Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
* [LOLBAS Project](https://lolbas-project.github.io/) – danh sách đầy đủ LOLBins.
* Elastic Detection Rule repo: SMB via LOLBins.

---

