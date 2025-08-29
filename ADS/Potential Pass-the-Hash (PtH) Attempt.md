
---

# Potential Pass-the-Hash (PtH) Attempt

## Goal

Phát hiện hành vi **Pass-the-Hash (PtH)** – kỹ thuật kẻ tấn công sử dụng hash mật khẩu đã đánh cắp thay cho plaintext password để xác thực vào hệ thống Windows, từ đó thực hiện lateral movement mà không cần biết mật khẩu gốc.

## Categorization

* [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) / [Use Alternate Authentication Material (T1550)](https://attack.mitre.org/techniques/T1550/)

## Strategy Abstract

Rule dựa trên các chỉ số trong **Windows Security Event Logs**:

* **Sự kiện đăng nhập thành công** (`event.outcome: success`).
* **Logon type = 9 (NewCredentials)** → đây là loại đăng nhập thường thấy khi dùng `runas /netonly` hoặc PtH.
* **LogonProcessName = "seclogo"** → đặc trưng của NewCredentials logon.
* **User SID** hợp lệ: `S-1-5-21-*` hoặc `S-1-12-1-*` (chỉ tài khoản người dùng domain/local, bỏ qua các built-in accounts).

## Technical Context

* **Nguồn dữ liệu**: Windows Security Event Logs.

* **Index sử dụng**:

  * `winlogbeat-*`
  * `logs-windows.forwarded*`
  * `logs-system.security*`

* **Logic rule (KQL/Kuery)**:

  ```kuery
  host.os.type:"windows" and
  event.category:"authentication" and event.action:"logged-in" and
  winlog.logon.type:"NewCredentials" and event.outcome:"success" and
  user.id:(S-1-5-21-* or S-1-12-1-*) and
  winlog.event_data.LogonProcessName:"seclogo"
  ```

* **Ý nghĩa**:

  * Logon type **9 (NewCredentials)** thường được attacker lợi dụng cho PtH.
  * `seclogo` là Logon Process Name được Windows sử dụng trong trường hợp này.
  * Rule lọc chỉ người dùng domain/local SID để tránh noise từ service accounts hệ thống.

* **Ví dụ tấn công**:

  * Attacker có hash NTLM của user domain → dùng **Mimikatz** hoặc công cụ tương tự để đăng nhập:

    ```cmd
    sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<hash>
    ```
  * Kết quả: Event logon type 9 với process `seclogo` và thành công (success).

## Blind Spots and Assumptions

* Không phát hiện PtH khi attacker inject trực tiếp hash vào session đang tồn tại thay vì tạo new logon.
* Một số tool hoặc script hợp pháp có thể sử dụng `runas /netonly` → cũng tạo logon type 9 (false positive).
* Rule giả định rằng bất kỳ logon type 9 "thành công" đều đáng nghi, nhưng vẫn cần đối chiếu với hoạt động quản trị hợp lệ.

## False Positives

* Quản trị viên dùng `runas /netonly` để chạy ứng dụng với credential khác.
* Một số phần mềm quản trị từ xa hoặc automation tool có thể trigger logon type 9.
  👉 Giải pháp: baseline hoạt động hợp pháp trong môi trường và loại trừ tài khoản, host hoặc ứng dụng hợp lệ.

## Validation

Để kiểm thử:

1. Trên máy thử nghiệm, dùng lệnh:

   ```cmd
   runas /netonly /user:DOMAIN\testuser cmd.exe
   ```

   → Sinh event logon type 9 (NewCredentials).
2. Hoặc dùng Mimikatz để mô phỏng PtH.
3. Kiểm tra SIEM để xác nhận rule tạo cảnh báo.

## Priority

* **Medium**: Khi phát hiện logon type 9 nhưng account/host nằm trong baseline hợp lệ.
* **High**: Khi tài khoản đặc quyền (admin, domain admin, service accounts nhạy cảm) thực hiện logon type 9 bất thường.

## Response

1. Xác định tài khoản nào thực hiện logon type 9 (SID, username).
2. Xác minh **host nguồn** và **ứng dụng** đã tạo logon.
3. Đối chiếu với hoạt động quản trị hợp pháp (có phải admin dùng `runas` không).
4. Nếu nghi ngờ PtH:

   * Cô lập host bị ảnh hưởng.
   * Thu thập memory dump để tìm dấu vết công cụ tấn công (Mimikatz, Rubeus, …).
   * Kiểm tra lateral movement tiếp theo từ tài khoản đó.
   * Reset credential liên quan.

## Additional Resources

* MITRE ATT\&CK: [Pass-the-Hash (T1550.002)](https://attack.mitre.org/techniques/T1550/002/)
* Microsoft Docs: [Logon Types](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
* Mimikatz: [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)

---


