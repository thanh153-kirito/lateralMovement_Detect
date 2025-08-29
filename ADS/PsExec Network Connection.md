
---

# PsExec Network Connection

## Goal

Phát hiện việc sử dụng công cụ **PsExec.exe** (thuộc bộ SysInternals) để tạo kết nối mạng ra ngoài. PsExec thường được kẻ tấn công dùng cho **lateral movement**, thực thi lệnh từ xa và triển khai payload trên hệ thống mục tiêu.

## Categorization

* [Execution](https://attack.mitre.org/tactics/TA0002/) / [System Services](https://attack.mitre.org/techniques/T1569/)
* [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) / [Remote Services](https://attack.mitre.org/techniques/T1021/)
* [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) / [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)

## Strategy Abstract

Rule phát hiện:

1. **Process PsExec.exe được khởi chạy** với tham số `-accepteula` (chấp nhận EULA lần đầu chạy).
2. Sau đó, trong cùng session process (`process.entity_id`), tiến trình PsExec.exe thực hiện **kết nối mạng**.

Các đường dẫn PsExec hợp lệ (của Docusnap, Cynet) được loại trừ để giảm false positives.

## Technical Context

* **Nguồn dữ liệu**: Elastic Defend, Sysmon.

* **Index sử dụng**:

  * `winlogbeat-*`
  * `logs-endpoint.events.process-*`
  * `logs-endpoint.events.network-*`
  * `logs-windows.sysmon_operational-*`

* **Logic rule (EQL)**:

  ```eql
  sequence by process.entity_id
    [process where host.os.type == "windows" and process.name : "PsExec.exe" and event.type == "start" and
     process.args : "-accepteula" and
     not process.executable : (
       "?:\\ProgramData\\Docusnap\\Discovery\\discovery\\plugins\\17\\Bin\\psexec.exe",
       "?:\\Docusnap 11\\Bin\\psexec.exe",
       "?:\\Program Files\\Docusnap X\\Bin\\psexec.exe",
       "?:\\Program Files\\Docusnap X\\Tools\\dsDNS.exe") and
     not process.parent.executable : 
       "?:\\Program Files (x86)\\Cynet\\Cynet Scanner\\CynetScanner.exe"]
    [network where host.os.type == "windows" and process.name : "PsExec.exe"]
  ```

* **Ý nghĩa**:

  * `-accepteula` thường xuất hiện khi PsExec chạy lần đầu trên máy (dấu hiệu đáng chú ý).
  * PsExec thường dùng để:

    * Tạo dịch vụ từ xa trên máy mục tiêu.
    * Chạy command hoặc copy file qua SMB (\ADMIN\$).
    * Thực thi payload (vd: ransomware, backdoor).

* **Ví dụ tấn công**:

  ```cmd
  PsExec.exe \\targethost -u domain\admin -p Password123 cmd.exe
  ```

  → Tạo kết nối SMB/RPC và spawn `cmd.exe` trên host đích.

## Blind Spots and Assumptions

* Nếu attacker rename PsExec.exe thành tên khác (vd: `psexsvc.exe`, `utility.exe`) thì rule có thể bỏ sót.
* Rule dựa trên tham số `-accepteula`, nên nếu PsExec đã được chạy trước đó → không phát hiện.
* Một số tool tương tự (vd: Impacket’s psexec.py) không bị rule này bắt.

## False Positives

* PsExec được dùng hợp pháp trong các kịch bản:

  * Admin IT triển khai phần mềm hoặc script.
  * Các công cụ quản trị/bảo mật (như Docusnap, Cynet) có PsExec tích hợp.
* Các trường hợp này đã được loại trừ trong rule, nhưng baseline cụ thể từng môi trường vẫn cần thiết.

## Validation

Để kiểm thử:

1. Tải PsExec từ SysInternals.
2. Thực thi lệnh từ một máy tới máy khác:

   ```cmd
   PsExec.exe \\targethost cmd.exe -accepteula
   ```
3. Trên máy giám sát, xác nhận:

   * Event process PsExec.exe được khởi chạy.
   * Event network cho thấy PsExec.exe mở kết nối ra ngoài.
4. Kiểm tra SIEM để xác nhận rule sinh cảnh báo.

## Priority

* **Low**: Khi chỉ phát hiện PsExec chạy với `-accepteula` nhưng không có hành vi rõ ràng.
* **Medium**: Khi PsExec thực hiện kết nối mạng tới host khác.
* **High**: Nếu PsExec được dùng để spawn tiến trình nhạy cảm (`cmd.exe`, `powershell.exe`, `mimikatz.exe`) hoặc xuất hiện ngoài lịch sử baseline hợp lệ.

## Response

1. Kiểm tra **source user** và **host** đã chạy PsExec.
2. Xác minh **destination IP/hostname** của kết nối.
3. Xem tiến trình spawn từ PsExec (nếu có).
4. Liên hệ với admin để xác nhận hoạt động có hợp lệ.
5. Nếu nghi ngờ tấn công:

   * Cô lập host phát sinh PsExec.
   * Thu thập logs PsExec và SMB để phân tích.
   * Kiểm tra lateral movement tới các hệ thống khác.
   * Reset credential bị lộ hoặc bị dùng sai mục đích.

## Additional Resources

* MITRE ATT\&CK: [System Services (T1569)](https://attack.mitre.org/techniques/T1569/)
* MITRE ATT\&CK: [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
* MITRE ATT\&CK: [Lateral Tool Transfer (T1570)](https://attack.mitre.org/techniques/T1570/)
* Microsoft SysInternals: [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)

---

