

---

# RDP Enabled via Registry

## Goal

Phát hiện hành vi **sửa đổi registry để bật Remote Desktop Protocol (RDP)**. Đây là hành động thường được attacker sử dụng để chuẩn bị cho **lateral movement** hoặc thiết lập **truy cập backdoor**.

## Categorization

* **MITRE ATT\&CK**:

  * Lateral Movement (TA0008) → [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
  * Defense Evasion (TA0005) → [Modify Registry (T1112)](https://attack.mitre.org/techniques/T1112/)

## Strategy Abstract

RDP được bật/tắt thông qua key registry:

```
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
```

* Nếu giá trị `fDenyTSConnections = 0` → RDP **được bật**.
* Nếu = 1 → RDP **bị tắt**.

Attacker thường thay đổi key này (ví dụ qua PowerShell, reg.exe, script hoặc malware) để mở RDP rồi thực hiện lateral movement. Rule này theo dõi **registry change events**, lọc ra khi `fDenyTSConnections` bị set về `0`, và loại bỏ các tiến trình hợp pháp (như `SystemPropertiesRemote.exe`).

## Technical Context

* **Nguồn dữ liệu**:

  * Elastic Defend / Elastic Endgame
  * Sysmon (Registry Event ID 13)
  * Windows Event Logs
  * MDE, SentinelOne

* **Index patterns**:

  * `logs-endpoint.events.registry-*`
  * `winlogbeat-*`
  * `logs-windows.sysmon_operational-*`
  * `endgame-*`
  * `logs-m365_defender.event-*`
  * `logs-sentinel_one_cloud_funnel.*`

* **Logic Rule (EQL)**:

  ```eql
  registry where host.os.type == "windows" and event.type == "change" and
    registry.path : (
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\fDenyTSConnections",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\fDenyTSConnections",
      "MACHINE\\*ControlSet*\\Control\\Terminal Server\\fDenyTSConnections"
    ) and
    registry.data.strings : ("0", "0x00000000") and
    not process.executable : (
      "?:\\Windows\\System32\\SystemPropertiesRemote.exe", 
      "?:\\Windows\\System32\\SystemPropertiesComputerName.exe", 
      "?:\\Windows\\System32\\SystemPropertiesAdvanced.exe", 
      "?:\\Windows\\System32\\SystemSettingsAdminFlows.exe", 
      "?:\\Windows\\WinSxS\\*\\TiWorker.exe", 
      "?:\\Windows\\system32\\svchost.exe"
    )
  ```

* **Ý nghĩa kỹ thuật**:

  * Rule tìm các thay đổi registry liên quan đến RDP.
  * Nếu key bị set về `0` mà không phải bởi tiến trình UI quản trị hợp pháp → nhiều khả năng attacker hoặc malware bật RDP.

* **Ví dụ tấn công**:

  ```powershell
  # Bật RDP qua PowerShell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0
  ```

## Blind Spots and Assumptions

* Nếu attacker dùng công cụ quản trị hợp pháp (vd: SystemPropertiesRemote.exe) thì rule sẽ **bị loại trừ** → có thể bỏ sót tấn công nội bộ.
* Nếu RDP được bật qua GPO (Group Policy) thay vì sửa registry local → rule không phát hiện.
* Không bao quát trường hợp attacker thay đổi Firewall để mở cổng RDP.

## False Positives

* Admin bật RDP thủ công để hỗ trợ từ xa.
* Một số phần mềm quản trị IT có thể chỉnh registry này tự động.
  👉 Cần baseline: nếu nhiều máy chủ cùng bị bật RDP bất thường trong thời gian ngắn → khả năng cao là malicious.

## Validation

1. Trên máy test, chạy:

   ```cmd
   reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
   ```
2. Kiểm tra logs → Rule cần generate alert.
3. Thử bật RDP qua GUI (`SystemPropertiesRemote.exe`) → rule **không alert** (vì có exclusion).

## Priority

* **Medium (47)** vì:

  * Bật RDP không phải luôn malicious.
  * Tuy nhiên, khi kết hợp với dấu hiệu khác (brute force login, unusual source IP) → **cực kỳ nguy hiểm**.

## Response

1. Xác minh tiến trình nào chỉnh sửa registry.
2. Nếu không phải hoạt động admin hợp pháp → cô lập endpoint.
3. Kiểm tra xem có kết nối RDP nào được thực hiện sau khi key thay đổi.
4. Reset mật khẩu tài khoản bị lạm dụng (nếu có).
5. Kiểm tra lateral movement khác (PsExec, WinRM, WMI).

## Additional Resources

* [MITRE ATT\&CK – T1112 Modify Registry](https://attack.mitre.org/techniques/T1112/)
* [MITRE ATT\&CK – T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)
* Microsoft Docs – [Enable Remote Desktop via Registry](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow)

---


