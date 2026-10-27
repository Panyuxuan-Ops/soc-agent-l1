# MITRE ATT&CK 技术摘要（L1 精简版）

> 本文件用于 Dify 知识库。内容为 ATT&CK Enterprise 的小型子集，不是全量 ATT&CK。

## T1110 - Brute Force

- Tactics: Credential Access
- Keywords: brute force, 暴力破解, ssh, rdp, failed password, 登录失败, authentication failure, invalid user, 撞库
- URL: https://attack.mitre.org/techniques/T1110/

攻击者通过反复猜测口令获取有效账户。常见于 SSH、RDP、VPN、Web 登录接口，短时间大量失败认证是核心特征。

检测提示：关注同一源 IP 在短时间内的认证失败次数、失败账户数量、是否最终出现成功登录；区分扫描器与真实爆破。

## T1078 - Valid Accounts

- Tactics: Initial Access, Persistence, Privilege Escalation, Defense Evasion
- Keywords: valid account, 合法账户, 异常登录, impossible travel, 异地登录, successful login, 账户滥用, 服务账户
- URL: https://attack.mitre.org/techniques/T1078/

攻击者使用真实存在的账户登录，绕过弱口令告警。单个登录事件可能完全正常，需要结合时间、地点、设备与行为基线判断。

检测提示：对比登录时间、源 IP 地理位置、设备指纹与历史行为；关注服务账户在非计划时间登录。

## T1059 - Command and Scripting Interpreter

- Tactics: Execution
- Keywords: powershell, cmd.exe, bash, shell, 命令执行, 脚本, python, curl, wget, encodedcommand
- URL: https://attack.mitre.org/techniques/T1059/

攻击者利用系统自带命令解释器执行命令或脚本，降低引入恶意二进制的门槛。

检测提示：关注父进程异常的 shell 调用、编码后的 PowerShell、从临时目录执行的脚本与下载后立即执行。

## T1190 - Exploit Public-Facing Application

- Tactics: Initial Access
- Keywords: exploit, 漏洞利用, web shell, rce, sql injection, 命令注入, struts, log4j, 公开应用, webshell
- URL: https://attack.mitre.org/techniques/T1190/

攻击者利用对外暴露的 Web、VPN、邮件等应用漏洞获得初始访问，常伴随异常 HTTP 请求与 WebShell 落地。

检测提示：结合 WAF/访问日志中的攻击载荷、异常响应码、Web 目录新增文件与进程创建。

## T1133 - External Remote Services

- Tactics: Initial Access, Persistence
- Keywords: vpn, rdp, ssh, 远程服务, 外部远程, citrix, fortinet, exchange, 远程登录
- URL: https://attack.mitre.org/techniques/T1133/

攻击者通过 VPN、RDP、SSH 等对外远程服务进入内网，或借此维持访问。

检测提示：关注来自异常地理位置的远程服务登录、非工作时段登录、失败后成功的模式。

## T1021 - Remote Services

- Tactics: Lateral Movement
- Keywords: lateral movement, 横向移动, smb, rdp, winrm, ssh, psexec, wmi, 远程服务
- URL: https://attack.mitre.org/techniques/T1021/

攻击者使用合法远程服务在主机之间移动，流量往往与运维行为相似。

检测提示：建立主机间访问基线，关注新出现的源/目的主机对、异常账户与非工作时段连接。

## T1046 - Network Service Discovery

- Tactics: Discovery
- Keywords: port scan, 端口扫描, nmap, masscan, 服务发现, network scan, 端口探测
- URL: https://attack.mitre.org/techniques/T1046/

攻击者扫描网络服务以寻找可利用入口，常产生大量短连接与异常端口访问。

检测提示：关注单源 IP 对多端口/多主机的连接尝试，以及防火墙拒绝日志的突增。

## T1595 - Active Scanning

- Tactics: Reconnaissance
- Keywords: active scanning, 主动扫描, web scan, 目录扫描, nikto, nuclei, dirbuster, 400 error, 扫描器
- URL: https://attack.mitre.org/techniques/T1595/

攻击者在入侵前主动探测目标资产、目录与技术栈，常表现为大量 4xx 响应或敏感路径请求。

检测提示：关注短时间内对 /.env、/admin、/phpmyadmin 等路径的请求，以及单一 UA 的高频访问。

## T1566 - Phishing

- Tactics: Initial Access
- Keywords: phishing, 钓鱼, 邮件, attachment, 恶意附件, 链接, credential harvest, 鱼叉
- URL: https://attack.mitre.org/techniques/T1566/

攻击者通过邮件或消息投递恶意链接/附件，诱导用户执行或泄露凭据。

检测提示：结合邮件网关告警、附件哈希、域名信誉与用户点击行为；单看邮件日志容易漏报。

## T1486 - Data Encrypted for Impact

- Tactics: Impact
- Keywords: ransomware, 勒索, encrypt, 加密文件, ransom note, 扩展名变更, mass file rename
- URL: https://attack.mitre.org/techniques/T1486/

勒索软件批量加密文件并索要赎金，通常伴随文件扩展名变化、卷影副本删除与勒索信落地。

检测提示：关注短时间大量文件写入/重命名、已知勒索扩展名、勒索信文件名与备份删除命令。

## T1490 - Inhibit System Recovery

- Tactics: Impact
- Keywords: vssadmin, shadow copy, 卷影副本, wbadmin, bcdedit, recovery, 删除备份, inhibit recovery
- URL: https://attack.mitre.org/techniques/T1490/

攻击者删除卷影副本、禁用恢复分区或破坏备份，使受害者难以恢复。

检测提示：关注 vssadmin delete shadows、wbadmin delete catalog、bcdedit recovery 等命令。

## T1053 - Scheduled Task/Job

- Tactics: Execution, Persistence, Privilege Escalation
- Keywords: schtasks, cron, 定时任务, scheduled task, at.exe, systemd timer, 计划任务
- URL: https://attack.mitre.org/techniques/T1053/

攻击者创建计划任务实现持久化或定时执行恶意载荷。

检测提示：关注新创建的任务、异常执行路径、短周期触发与 SYSTEM/root 权限任务。

## T1543 - Create or Modify System Process

- Tactics: Persistence, Privilege Escalation
- Keywords: service, 服务, systemd, launchd, windows service, 创建服务, sc create
- URL: https://attack.mitre.org/techniques/T1543/

攻击者创建或修改系统服务，以系统权限运行恶意代码并实现持久化。

检测提示：关注新服务注册、服务二进制路径位于临时目录、服务账户权限异常。

## T1547 - Boot or Logon Autostart Execution

- Tactics: Persistence, Privilege Escalation
- Keywords: run key, 注册表启动项, autostart, 开机自启, startup folder, init.d, rc.local
- URL: https://attack.mitre.org/techniques/T1547/

攻击者通过启动项、注册表 Run 键或登录脚本实现开机/登录自动执行。

检测提示：关注新增启动项、指向临时目录或混淆脚本的启动命令。

## T1055 - Process Injection

- Tactics: Defense Evasion, Privilege Escalation
- Keywords: process injection, 进程注入, createremotethread, apc, ptrace, mimikatz, 内存注入
- URL: https://attack.mitre.org/techniques/T1055/

攻击者将代码注入其他进程，隐藏执行并可能提升权限。

检测提示：关注跨进程内存写入、远程线程创建、异常模块加载与 EDR 行为告警。

## T1003 - OS Credential Dumping

- Tactics: Credential Access
- Keywords: credential dumping, 凭据窃取, mimikatz, lsass, sam, ntds.dit, procdump, hashdump
- URL: https://attack.mitre.org/techniques/T1003/

攻击者从内存或磁盘提取账户哈希、明文口令或票据。

检测提示：关注对 lsass 的异常访问、procdump 使用、SAM/NTDS.dit 读取与高权限账户的异常行为。

## T1112 - Modify Registry

- Tactics: Defense Evasion
- Keywords: registry, 注册表, reg add, regedit, disable defender, 篡改注册表
- URL: https://attack.mitre.org/techniques/T1112/

攻击者修改注册表以关闭安全控制、隐藏痕迹或配置持久化。

检测提示：关注安全相关注册表键被修改、Defender 被禁用、注册表导出与远程注册表访问。

## T1105 - Ingress Tool Transfer

- Tactics: Command and Control
- Keywords: download, 下载, curl, wget, certutil, bitsadmin, ingress tool, 传输工具
- URL: https://attack.mitre.org/techniques/T1105/

攻击者从外部下载工具或载荷到受害主机。

检测提示：关注 curl/wget/certutil 下载可执行文件、临时目录落地与随后执行。

## T1071 - Application Layer Protocol

- Tactics: Command and Control
- Keywords: c2, command and control, http, dns, beacon, 心跳, 命令控制, 恶意外联
- URL: https://attack.mitre.org/techniques/T1071/

攻击者使用 HTTP、DNS 等常见应用层协议与 C2 通信，绕过基于端口的检测。

检测提示：结合域名信誉、周期性心跳、异常 User-Agent 与 DNS 隧道特征；单条日志往往不足以定性。

## T1041 - Exfiltration Over C2 Channel

- Tactics: Exfiltration
- Keywords: exfiltration, 数据外传, c2 channel, 数据泄露, upload, 外发流量
- URL: https://attack.mitre.org/techniques/T1041/

攻击者通过既有 C2 通道向外传输数据。

检测提示：关注内网主机向外部的大流量上传、与已知 C2 域名通信、非业务时段的外联。

## T1567 - Exfiltration Over Web Service

- Tactics: Exfiltration
- Keywords: web service, 云盘, pastebin, github, telegram, 数据外传, 网盘
- URL: https://attack.mitre.org/techniques/T1567/

攻击者利用合法的云存储、代码托管或消息服务外传数据，流量看似正常。

检测提示：关注对云存储/粘贴站的上传行为、异常大文件与个人账户使用。

## T1070 - Indicator Removal

- Tactics: Defense Evasion
- Keywords: clear log, 日志清除, wevtutil, history -c, shred, 删除日志, anti-forensics
- URL: https://attack.mitre.org/techniques/T1070/

攻击者删除日志、命令历史或文件时间戳以逃避检测与取证。

检测提示：关注日志服务停止、事件日志被清空、命令历史被删除与时间戳异常。

## T1087 - Account Discovery

- Tactics: Discovery
- Keywords: account discovery, 账户发现, net user, whoami, ldapsearch, 枚举用户, domain users
- URL: https://attack.mitre.org/techniques/T1087/

攻击者枚举本地或域账户，为后续凭据攻击与横向移动做准备。

检测提示：关注批量账户查询、LDAP 枚举与异常账户权限查询。

## T1082 - System Information Discovery

- Tactics: Discovery
- Keywords: systeminfo, uname -a, 系统信息, hostname, os version, whoami, 环境探测
- URL: https://attack.mitre.org/techniques/T1082/

攻击者收集操作系统、补丁与硬件信息，以选择后续利用方式。

检测提示：单条命令常见，需结合上下文；关注入侵后短时间内多次系统信息查询。

## T1018 - Remote System Discovery

- Tactics: Discovery
- Keywords: remote system discovery, net view, arp -a, ping sweep, 主机发现, 内网探测
- URL: https://attack.mitre.org/techniques/T1018/

攻击者枚举网络中的其他主机，为横向移动建立目标列表。

检测提示：关注批量 ping、ARP 扫描、net view 与内网段的异常探测流量。

## T1505 - Server Software Component

- Tactics: Persistence
- Keywords: web shell, webshell, 后门, server component, iis module, tomcat valve, php shell
- URL: https://attack.mitre.org/techniques/T1505/

攻击者在 Web 服务器中植入 WebShell 或恶意模块，以维持访问。

检测提示：关注 Web 目录新增脚本、异常 POST 参数、服务器进程派生子 shell。

## T1552 - Unsecured Credentials

- Tactics: Credential Access
- Keywords: unsecured credentials, 明文密码, 配置文件, .env, credentials, 密钥泄露, aws key
- URL: https://attack.mitre.org/techniques/T1552/

攻击者从配置文件、环境变量、命令行历史中寻找未加密的凭据。

检测提示：关注对 .env、config、.git-credentials 等文件的异常读取与仓库泄露。

## T1098 - Account Manipulation

- Tactics: Persistence, Privilege Escalation
- Keywords: account manipulation, 账户篡改, add user, usermod, sudoers, 加入管理员组, 权限提升
- URL: https://attack.mitre.org/techniques/T1098/

攻击者修改账户属性、组成员关系或 sudo 权限以维持访问。

检测提示：关注 /etc/sudoers、/etc/passwd、管理员组变更与新增账户。

## T1136 - Create Account

- Tactics: Persistence
- Keywords: create account, 创建账户, useradd, net user /add, 后门账户, 新用户
- URL: https://attack.mitre.org/techniques/T1136/

攻击者创建本地或域账户作为后门。

检测提示：关注新账户创建、账户命名规律异常、创建后立即登录。

## T1548 - Abuse Elevation Control Mechanism

- Tactics: Privilege Escalation, Defense Evasion
- Keywords: sudo, sudoers, uac, setuid, 提权, 权限提升, elevation, runas
- URL: https://attack.mitre.org/techniques/T1548/

攻击者滥用 sudo、UAC、setuid 等合法提权机制获得更高权限。

检测提示：关注 sudoers 变更、异常 sudo 命令、setuid 文件新增与 UAC 绕过行为。

## T1222 - File and Directory Permissions Modification

- Tactics: Defense Evasion
- Keywords: chmod, chown, icacls, 权限修改, 文件权限, 777, attrib
- URL: https://attack.mitre.org/techniques/T1222/

攻击者修改文件权限以便执行、读取或隐藏恶意文件。

检测提示：关注敏感目录权限被放宽、chmod 777、系统文件属主变更。

## T1569 - System Services

- Tactics: Execution
- Keywords: systemctl, service, sc start, 服务执行, system services, 启动服务
- URL: https://attack.mitre.org/techniques/T1569/

攻击者通过系统服务执行命令或载荷。

检测提示：关注新服务启动、服务二进制被替换、服务启动后派生异常进程。

## T1204 - User Execution

- Tactics: Execution
- Keywords: user execution, 用户执行, 双击, 恶意宏, attachment opened, 钓鱼附件
- URL: https://attack.mitre.org/techniques/T1204/

攻击者诱导用户主动执行恶意文件或链接。

检测提示：结合邮件、下载、宏启用与进程创建链；单条告警通常需要人工确认。

## T1611 - Escape to Host

- Tactics: Privilege Escalation
- Keywords: container escape, 容器逃逸, docker, privileged container, host mount, k8s escape
- URL: https://attack.mitre.org/techniques/T1611/

攻击者从容器逃逸到宿主机，通常利用特权容器、挂载或内核漏洞。

检测提示：关注特权容器、宿主机目录挂载、容器内 docker.sock 访问与异常内核模块。

## T1529 - System Shutdown/Reboot

- Tactics: Impact
- Keywords: shutdown, reboot, 关机, 重启, system shutdown, 破坏可用性
- URL: https://attack.mitre.org/techniques/T1529/

攻击者关闭或重启系统以中断服务或配合破坏行为。

检测提示：关注非计划关机、批量主机重启与维护窗口外的重启命令。

## T1562 - Impair Defenses

- Tactics: Defense Evasion
- Keywords: disable defender, 关闭杀软, 停止服务, impair defenses, 防火墙关闭, edr uninstall
- URL: https://attack.mitre.org/techniques/T1562/

攻击者关闭或篡改安全产品、日志与防护策略。

检测提示：关注安全服务停止、防护策略被修改、Agent 被卸载与日志采集中断。

## T1027 - Obfuscated Files or Information

- Tactics: Defense Evasion
- Keywords: obfuscation, 混淆, base64, encoded, packed, 加密载荷, powershell -enc
- URL: https://attack.mitre.org/techniques/T1027/

攻击者通过编码、加密或打包隐藏恶意内容。

检测提示：关注长 Base64 参数、编码 PowerShell、异常高熵文件与多层解码链。

## T1219 - Remote Access Software

- Tactics: Command and Control
- Keywords: anydesk, teamviewer, remote access, 远控软件, 向日葵, todesk, rustdesk
- URL: https://attack.mitre.org/techniques/T1219/

攻击者使用合法远控软件维持访问，流量常被误认为正常运维。

检测提示：关注非 IT 资产安装远控软件、异常时段连接与陌生 ID 登录。

