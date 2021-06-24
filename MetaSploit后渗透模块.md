# MetaSploit后渗透模块

`msf6 > search type:post platform:linux name:gather`

MetaSploit后渗透模块整理，方便使用。

[toc]

## 多平台后渗透模块

### 凭据窃取

| Metasploit module                       | Description                                                  | Note/Platforms                                               |
| :-------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/multi/gather/docker_creds          | 该模块将收集目标机器上所有用户的 .docker 目录的内容。如果用户已经推送到 docker hub，则密码可能保存在 base64 中（Default）。 | Platforms: bsd, linux, osx, unix ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/docker_creds.rb)) |
| post/multi/gather/filezilla_client_cred | 此模块将从 FileZilla FTP 客户端收集凭据。                    | Platforms: bsd, linux, osx, unix, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/filezilla_client_cred.rb)) |
| post/multi/gather/jboss_gather          | 此模块可用于提取版本 4,5 和 6 的 Jboss 管理员密码。          | Platforms: linux, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/jboss_gather.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/jboss_gather.md)) |
| post/multi/gather/jenkins_gather        | 该模块可用于提取保存的 Jenkins 凭证、用户令牌、SSH 密钥和机密。有趣的文件将与合并的 csv 输出一起存储在 loot 中。 | Platforms: linux, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/jenkins_gather.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/jenkins_gather.md)) |
| post/multi/gather/maven_creds           | 该模块将收集目标机器上所有用户的settings.xml（Apache Maven 配置文件）的内容。 | Platforms: bsd, linux, osx, unix, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/maven_creds.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/maven_creds.md)) |
| post/multi/gather/pgpass_creds          | 该模块将收集所有用户的 .pgpass 或 pgpass.conf 文件的内容并解析它们以获得凭据。 | Platforms: linux, bsd, unix, osx, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/pgpass_creds.rb)) |
| post/multi/gather/ssh_creds             | 该模块将收集目标机器上所有用户的 .ssh 目录的内容。此外，还会下载known_hosts 和authorized_keys 文件。 | Platforms: bsd, linux, osx, unix ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/ssh_creds.rb)) |
| post/multi/gather/thunderbird_creds     | 此模块将通过下载必要的文件（例如“signons.sqlite”、“key3.db”和“cert8.db”）从 Mozilla Thunderbird 收集凭据，以便使用第三方工具进行离线解密。 | Platforms: linux, osx, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/thunderbird_creds.rb)) |
| post/multi/gather/tomcat_gather         | 该模块将尝试从机器上运行的 Tomcat 服务收集凭据。             | Platforms: win, linux ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/tomcat_gather.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/tomcat_gather.md)) |

### 多平台提权模块

| Metasploit module                         | Description                                                  | Note/Platforms                                               |
| :---------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/multi/escalate/cups_root_file_read   | 该模块利用了 CUPS < 1.6.2（一种开源打印系统）中的 CVE-2012-5519 漏洞。该漏洞允许读取系统上的任意文件（以 root 身份）。 | Platforms: linux, osx ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/escalate/cups_root_file_read.rb), [ref1](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=692791)) |
| post/multi/recon/local_exploit_suggester  | 该模块建议可以使用的本地 Meterpreter 漏洞。漏洞利用是根据目标的体系结构、会话类型和平台建议的。 | Platforms: all_platforms ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/recon/local_exploit_suggester.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/recon/local_exploit_suggester.md)) |
| post/multi/recon/multiport_egress_traffic | 该模块生成跨端口序列的 TCP 或 UDP 流量，对于查找防火墙漏洞和出口过滤非常有用。 | Platforms: linux, osx, unix, solaris, bsd, windows ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/recon/multiport_egress_traffic.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/recon/multiport_egress_traffic.md)) |
| post/multi/recon/sudo_commands            | 此模块检查会话用户的 sudoers 配置并列出可通过 sudo 执行的命令。它还检查每个命令并报告由于较差的文件系统权限或允许执行已知对 privesc 有用的可执行文件而导致特权代码执行的潜在途径。 | Platforms: bsd, linux, osx, solaris, unix ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/recon/sudo_commands.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/recon/sudo_commands.md)) |

### 信息收集（多平台）

| Metasploit module                        | Description                                                  | Note/Platforms                                               |
| :--------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/multi/gather/dns_bruteforce         | 通过wordlist暴力破解子域和主机名。                           | Platforms: bsd, linux, osx, solaris, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/dns_bruteforce.rb)) |
| post/multi/gather/dns_reverse_lookup     | 使用操作系统包含的 DNS 查询命令执行 DNS 反向查找。           | Platforms: bsd, linux, osx, solaris, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/dns_reverse_lookup.rb)) |
| post/multi/gather/enum_software_versions | 该模块将收集所有已安装软件的详细信息，包括它们的版本和安装时间（如果可用），并将其保存到一个战利品文件中以备后用。这可用于确定哪些额外的漏洞可能影响目标机器。 | Platforms: win, linux, osx, bsd, solaris, android ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/enum_software_versions.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/enum_software_versions.md)) |
| post/multi/gather/enum_vbox              | 此模块将尝试枚举目标计算机上属于当前用户的所有 VirtualBox VM。 | Platforms: bsd, linux, osx, unix, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/enum_vbox.rb)) |
| post/multi/gather/env                    | 此模块打印出操作系统环境变量。                               | Platforms: linux, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/env.rb)) |
| post/multi/gather/find_vmx               | 此模块将尝试查找存储在目标上的任何 VMWare 虚拟机。           | Platforms: bsd, linux, osx, unix, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/find_vmx.rb)) |
| post/multi/gather/multi_command          | 该模块将从资源文件中读取shell命令，并在指定的meterpreter或shell会话中执行命令。 | Platforms: bsd, linux, osx, unix, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/multi_command.rb)) |
| post/multi/gather/ping_sweep             | 使用操作系统包含的 ping 命令执行 IPv4 ping 扫描。            | Platforms: bsd, linux, osx, solaris, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/ping_sweep.rb)) |
| post/multi/gather/resolve_hosts          | 从远程主机的角度将主机名解析为 IPv4 或 IPv6 地址。           | Platforms: win, python ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/resolve_hosts.rb)) |
| post/multi/gather/run_console_rc_file    | 该模块将从资源文件中读取控制台命令，并在指定的 Meterpreter 会话中执行命令。 | Platforms: win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/run_console_rc_file.rb)) |
| post/multi/gather/skype_enum             | 此模块将枚举Skype 帐户设置、联系人列表、通话记录、聊天记录、文件传输历史记录和语音邮件记录，将所有数据保存到CSV 文件以供分析。 | Platforms: osx, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/skype_enum.rb)) |
| post/multi/gather/wlan_geolocate         | 枚举目标设备可见的无线网络。（可选）通过收集本地无线网络并针对 Google API 执行查找来对目标进行地理定位。 | Platforms: android, osx, win, linux, bsd, solaris ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/wlan_geolocate.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/wlan_geolocate.md)) |

### 间谍/捕获（多平台）

| Metasploit module            | Description                                                  | Note/Platforms                                               |
| :--------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/multi/manage/record_mic | 此模块将启用并录制目标的麦克风。对于非 Windows 目标，请使用 Java meterpreter 才能使用此功能。 | Platforms: linux, osx, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/record_mic.rb)) |

### 通用/其他（多平台）

| Metasploit module                      | Description                                                  | Note/Platforms                                               |
| :------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/multi/general/close               | 此模块关闭指定的会话。这可以用作自动化任务的终结者。         | Platforms: linux, osx, unix, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/general/close.rb)) |
| post/multi/general/execute             | 此模块执行任意命令行。                                       | Platforms: linux, osx, unix, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/general/execute.rb)) |
| post/multi/general/wall                | 该模块根据需要利用 wall(1) 或 write(1) 实用程序向目标系统上的用户发送消息。 | Platforms: linux, osx, unix ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/general/wall.rb)) |
| post/multi/manage/autoroute            | 该模块通过现有的Meterpreter 会话启用网络路由。它使其他模块能够通过受感染的主机“旋转”。Autoadd 将从路由表和接口列表中搜索有效子网的会话，然后自动向它们添加路由。 | Platforms: ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/autoroute.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/manage/autoroute.md)) |
| post/multi/manage/multi_post           | 此模块将针对选择的meterpreter 或shell 会话以<module> <opt=val,opt=val> 格式执行宏文件中给出的模块列表。 | Platforms: linux, osx, solaris, unix, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/multi_post.rb)) |
| post/multi/manage/open                 | 该模块将通过嵌入的命令（例如“open”或“xdg-open”）在目标计算机上打开使用 URI 格式指定的任何文件或 URL。 | Platforms: osx, linux, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/open.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/manage/open.md)) |
| post/multi/manage/play_youtube         | 此模块将在指定的受感染系统上播放 YouTube 视频。它将在目标机器的本机浏览器中播放视频。 | Platforms: win, osx, linux, android, unix ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/play_youtube.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/manage/play_youtube.md)) |
| post/multi/manage/screensaver          | 该模块允许您打开或关闭目标计算机的屏幕保护程序并锁定当前会话。 | Platforms: linux, osx, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/screensaver.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/manage/screensaver.md)) |
| post/multi/manage/screenshare          | 该模块允许您通过本地浏览器窗口查看和控制目标计算机的屏幕。该模块不断对目标屏幕进行截图，并将所有鼠标和键盘事件中继到会话。 | Platforms: linux, win, osx ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/screenshare.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/manage/screenshare.md)) |
| post/multi/manage/set_wallpaper        | 该模块将设置指定会话的桌面壁纸背景。                         | Platforms: win, osx, linux, android ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/set_wallpaper.rb)) |
| post/multi/manage/shell_to_meterpreter | 此模块尝试将命令 Shell 升级到 Meterpreter。自动检测shell平台，并为目标选择最佳版本的meterpreter。 | Platforms: linux, osx, unix, solaris, bsd, windows ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/shell_to_meterpreter.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/manage/shell_to_meterpreter.md)) |
| post/multi/manage/upload_exec          | 此模块允许在远程系统上推送文件并执行它。                     | Platforms: win, unix, linux, osx, bsd, solaris ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/upload_exec.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/manage/upload_exec.md)) |
| post/multi/manage/zip                  | 该模块压缩远程系统上的文件或目录。                           | Platforms: win, linux ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/zip.rb)) |

## Windows后渗透模块

### 凭据窃取

| Metasploit module                                    | Description                                                  | Note/Platforms                                               |
| :--------------------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/capture/lockout_keylogger               | 此模块使用空闲时间和自然系统更改通过 Winlogon.exe 迁移和记录 Microsoft Windows 用户的密码，从而为用户提供虚假的安全感。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/capture/lockout_keylogger.rb), [ref1](http://blog.metasploit.com/2010/12/capturing-windows-logons-with.html)) |
| post/windows/gather/cachedump                        | 此模块使用注册表来提取已作为 GPO 设置结果缓存的存储域哈希。Windows 上的默认设置是存储最近十次成功登录。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/cachedump.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/cachedump.md), [ref1](http://lab.mediaservice.net/code/cachedump.rb)) |
| post/windows/gather/credentials/credential_collector | 该模块收集在主机上找到的凭据（哈希和访问令牌）并将它们存储在数据库中 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/credential_collector.rb)) |
| post/windows/gather/credentials/enum_cred_store      | 该模块将枚举 Microsoft 凭据存储并解密凭据。此模块只能访问由运行进程的用户创建的凭据。它无法解密域网络密码，但会显示用户名和位置。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/enum_cred_store.rb)) |
| post/windows/gather/credentials/mssql_local_hashdump | 该模块从 MSSQL 服务器中提取用户名和密码哈希并将它们存储为战利品。它在 mssql_local_auth_bypass 中使用相同的技术。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/mssql_local_hashdump.rb), [ref1](https://www.dionach.com/blog/easily-grabbing-microsoft-sql-server-password-hashes)) |
| post/windows/gather/credentials/outlook              | 该模块从 Windows 注册表中为 POP3/IMAP/SMTP/HTTP 帐户提取和解密保存的 Microsoft Outlook（版本 2002-2010）密码。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/outlook.rb)) |
| post/windows/gather/credentials/rdc_manager_creds    | 该模块提取和解密保存的 Microsoft 远程桌面连接管理器 (RDCMan) 密码和用户的 .RDG 文件。该模块将尝试查找为目标系统上的所有用户配置的文件。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/rdc_manager_creds.rb)) |
| post/windows/gather/credentials/skype                | 此模块为 Config.xml 文件中的 Windows Skype 客户端查找已保存的登录凭据。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/skype.rb), [ref1](https://www.recon.cx/en/f/vskype-part2.pdf), [ref2](http://insecurety.net/?p=427), [ref3](https://github.com/skypeopensource/tools)) |
| post/windows/gather/credentials/sso                  | 该模块将使用 Kiwi (Mimikatz) 扩展从本地安全机构收集明文单点登录凭据。空白密码不会存储在数据库中。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/sso.rb)) |
| post/windows/gather/credentials/windows_autologin    | 该模块从存储在 HKLM\Software\Microsoft\Windows NT\WinLogon 位置的注册表中提取纯文本 Windows AutoLogin 密码，所有用户都可以读取该密码。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/windows_autologin.rb), [ref1](https://support.microsoft.com/kb/315231), [ref2](http://core.yehg.net/lab/#tools.exploits)) |
| post/windows/gather/enum_snmp                        | 该模块将枚举 SNMP 服务配置，包括存储的社区字符串（SNMP 身份验证）。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_snmp.rb)) |
| post/windows/gather/hashdump                         | 此模块将使用注册表从 SAM 数据库转储本地用户帐户。            | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/hashdump.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/hashdump.md)) |
| post/windows/gather/lsa_secrets                      | 此模块将尝试枚举在注册表中的 HKEY_LOCAL_MACHINE\Security\Policy\Secrets\ 位置下找到的 LSA Secrets 密钥。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/lsa_secrets.rb)) |
| post/windows/gather/netlm_downgrade                  | 此模块将更改注册表值以启用 LM 质询哈希的发送，然后启动到 SMBHOST 数据存储的 SMB 连接。如果 SMB 服务器正在侦听，它将接收 NetLM 哈希。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/netlm_downgrade.rb), [ref1](https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks)) |
| post/windows/gather/phish_windows_credentials        | 该模块能够通过弹出登录提示对目标执行网络钓鱼攻击。当用户在登录提示中填写凭据时，凭据将发送给攻击者。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/phish_windows_credentials.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/phish_windows_credentials.md), [ref1](https://forsec.nl/2015/02/windows-credentials-phishing-using-metasploit)) |
| post/windows/gather/smart_hashdump                   | 这将从 SAM 数据库转储本地帐户。如果目标主机是域控制器，它将根据主机的权限级别、操作系统和角色使用适当的技术转储域帐户数据库。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/smart_hashdump.rb)) |
| post/windows/gather/word_unc_injector                | 此模块修改远程 .docx 文件，该文件将在打开时将存储的 netNTLM 凭据提交到远程主机。经验证可与 Microsoft Word 2003、2007、2010 和 2013 一起使用。为了获取哈希，可以使用辅助/服务器/捕获/smb 模块。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/word_unc_injector.rb), [ref1](https://web.archive.org/web/20140527232608/http://jedicorp.com/?p=534)) |
| post/windows/manage/wdigest_caching                  | 在 Windows 8/2012 或更高版本上，默认情况下禁用摘要安全提供程序 (WDIGEST)。此模块通过添加/更改 WDIGEST 提供程序的注册表项下的 UseLogonCredential DWORD 的值来启用/禁用凭据缓存。任何后续登录都将允许 mimikatz 从系统内存中恢复纯文本密码。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/wdigest_caching.rb)) |

### 凭据窃取(第三方应用程序)

| Metasploit module                                      | Description                                                  | Note/Platforms                                               |
| :----------------------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/gather/credentials/purevpn_cred_collector | 查找为 PureVPN 客户端存储的密码。                            | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/purevpn_cred_collector.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/credentials/purevpn_cred_collector.md), [ref1](https://www.trustwave.com/Resources/SpiderLabs-Blog/Credential-Leak-Flaws-in-Windows-PureVPN-Client/), [ref2](https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2018-010/?fid=11779)) |
| post/windows/gather/credentials/coreftp                | 该模块从注册表中的 CoreFTP FTP 客户端中提取保存的密码。      | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/coreftp.rb)) |
| post/windows/gather/credentials/dyndns                 | 该模块为 DynDNS 版本 4.1.8 提取用户名、密码和主机。          | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/dyndns.rb)) |
| post/windows/gather/credentials/epo_sql                | 此模块提取连接详细信息并解密 McAfee ePO 4.6 服务器使用的 SQL 数据库的保存密码。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/epo_sql.rb)) |
| post/windows/gather/credentials/filezilla_server       | 此模块将从已安装的 FileZilla FTP 服务器收集凭据。            | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/filezilla_server.rb)) |
| post/windows/gather/credentials/flashfxp               | 此模块从 FlashFXP 客户端及其 Sites.dat 文件中提取保存的 FTP 密码。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/flashfxp.rb)) |
| post/windows/gather/credentials/ftpnavigator           | 此模块从 FTP Navigator FTP 客户端提取保存的密码。它将解码保存的密码并将它们存储在数据库中。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/ftpnavigator.rb)) |
| post/windows/gather/credentials/ftpx                   | 此模块在 FTP Explorer (FTPx) 客户端的 profiles.xml 配置文件中查找保存的登录凭据。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/ftpx.rb)) |
| post/windows/gather/credentials/mcafee_vse_hashdump    | 此模块从用于锁定用户界面的 McAfee Virus Scan Enterprise (VSE) 中提取密码哈希。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/mcafee_vse_hashdump.rb), [ref1](https://www.dionach.com/blog/disabling-mcafee-on-access-scanning)) |
| post/windows/gather/credentials/mdaemon_cred_collector | 该模块提取 MDaemon 电子邮件服务器的密码。                    | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/mdaemon_cred_collector.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/credentials/mdaemon_cred_collector.md)) |
| post/windows/gather/credentials/mremote                | 该模块从 mRemote 连接管理器中提取保存的密码。mRemote 存储 RDP、VNC、SSH、Telnet、rlogin 和其他协议的连接。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/mremote.rb)) |
| post/windows/gather/credentials/securecrt              | 此模块将从 SecureCRT SSH 和 Telnet 客户端配置文件中提取凭据。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/securecrt.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/credentials/securecrt.md), [ref1](https://github.com/HyperSine/how-does-SecureCRT-encrypt-password/blob/master/doc/how-does-SecureCRT-encrypt-password.md)) |
| post/windows/gather/credentials/smartermail            | 此模块从 SmarterMail 'mailConfig.xml' 配置文件中提取并解密系统管理员密码。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/smartermail.rb), [ref1](http://www.gironsec.com/blog/tag/cracking-smartermail/)) |
| post/windows/gather/credentials/steam                  | 此模块将从设置为自动登录的帐户收集 Steam 会话信息。          | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/steam.rb)) |
| post/windows/gather/credentials/teamviewer_passwords   | 此模块将查找和解密存储的 TeamViewer 密码。                   | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/teamviewer_passwords.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/credentials/teamviewer_passwords.md), [ref1](https://whynotsecurity.com/blog/teamviewer/), [ref2](https://www.cnblogs.com/Kali-Team/p/12468066.html)) |
| post/windows/gather/credentials/vnc                    | 此模块从已知的注册表位置提取 VNC 服务器（UltraVNC、RealVNC、WinVNC、TightVNC 等）的 DES 加密密码。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/vnc.rb)) |
| post/windows/gather/credentials/winscp                 | 该模块从 WinSCP 客户端提取弱加密保存的密码，存储在注册表和 WinSCP.ini 配置文件中。请注意，如果使用主密码，则无法解密密码。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/winscp.rb)) |
| post/windows/gather/credentials/xshell_xftp_password   | 该模块可以解密来自 Xshell 和 Xftp – SSH、FTP 和 Telnet 客户端的存储（记住）密码。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/xshell_xftp_password.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/credentials/xshell_xftp_password.md), [ref1](https://github.com/HyperSine/how-does-Xmanager-encrypt-password/blob/master/doc/how-does-Xmanager-encrypt-password.md)) |
| post/windows/gather/enum_putty_saved_sessions          | 此模块将识别 Pageant (PuTTY Agent) 是否正在运行并从注册表中获取保存的会话信息，包括凭据。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_putty_saved_sessions.rb)) |
| post/windows/gather/enum_tomcat                        | 该模块将从基于Windows的Apache Tomcat中收集信息，包括安装路径、版本、端口、部署的Web应用程序、用户、密码、角色等 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_tomcat.rb)) |

### 信息收集 (Windows)

| Metasploit module                        | Description                                                  | Note/Platforms                                               |
| :--------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/gather/arp_scanner          | 该模块将通过 Meterpreter 会话为给定的 IP 范围执行 ARP 扫描。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/arp_scanner.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/arp_scanner.md)) |
| post/windows/gather/checkvm              | 此模块尝试确定系统是否在虚拟环境中运行，如果是，则确定是哪个。该模块支持 Hyper-V、VMWare、Virtual PC、VirtualBox、Xen 和 QEMU 的检测。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/checkvm.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/checkvm.md)) |
| post/windows/gather/dnscache_dump        | 此模块显示存储在 DNS 缓存中的记录。                          | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/dnscache_dump.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/dnscache_dump.md)) |
| post/windows/gather/enum_applications    | 此模块将枚举 Windows 系统上所有已安装的应用程序。            | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_applications.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/enum_applications.md)) |
| post/windows/gather/enum_artifacts       | 此模块将检查文件系统和注册表以查找特定工件。工件列表从 data/post/enum_artifacts_list.txt 或用户指定的文件中读取。任何匹配都会写入战利品。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_artifacts.rb)) |
| post/windows/gather/enum_av_excluded     | 此模块将从支持的 AV 产品中枚举文件、目录、进程和基于扩展的排除项，这些产品目前包括 Microsoft Defender、Microsoft Security Essentials/Antimalware 和 Symantec Endpoint Protection。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_av_excluded.rb)) |
| post/windows/gather/enum_computers       | 此模块将枚举主域中包含的计算机。                             | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_computers.rb)) |
| post/windows/gather/enum_files           | 此模块根据 FILE_GLOBS 选项递归下载文件。                     | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_files.rb)) |
| post/windows/gather/enum_hostfile        | 此模块返回目标系统Hosts文件中的条目列表。                    | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_hostfile.rb)) |
| post/windows/gather/enum_hyperv_vms      | 该模块将检查目标机器是否是 Hyper-V 主机，如果是，将返回主机上运行的所有 VM 的列表，以及它们的状态、版本等统计信息、CPU 使用率、正常运行时间和状态。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_hyperv_vms.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/enum_hyperv_vms.md)) |
| post/windows/gather/enum_logged_on_users | 此模块将枚举当前和最近登录的 Windows 用户。                  | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_logged_on_users.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/enum_logged_on_users.md)) |
| post/windows/gather/enum_patches         | 该模块将尝试根据 WMI 查询的结果枚举哪些补丁应用于 Windows 系统：SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_patches.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/enum_patches.md), [ref1](https://msdn.microsoft.com/en-us/library/aa394391(v=vs.85).aspx)) |
| post/windows/gather/enum_powershell_env  | 此模块将枚举 Microsoft Powershell 设置。                     | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_powershell_env.rb)) |
| post/windows/gather/enum_proxy           | 此模块从当前计算机中提取用户的代理设置。它还可以从另一个远程主机的特定 SID（用户）中提取代理设置。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_proxy.rb)) |
| post/windows/gather/enum_shares          | 此模块将枚举已配置和最近使用的文件共享。                     | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_shares.rb)) |
| post/windows/gather/enum_termserv        | 转储程序 此模块转储 RDP 会话的 MRU 和连接数据。              | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_termserv.rb)) |
| post/windows/gather/outlook              | 此模块允许使用 PowerShell 从本地 Outlook 安装中读取和搜索电子邮件。请注意，该模块正在操纵受害者的键盘/鼠标。如果受害者在目标系统上处于活动状态，他/她可能会注意到它。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/outlook.rb), [ref1](https://forsec.nl/2014/11/reading-outlook-using-metasploit)) |
| post/windows/gather/win_privs            | 此模块将打印是否启用了 UAC，并且当前帐户是否启用了 ADMIN。它还将打印 UID、前台会话 ID、系统状态和当前进程特权。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/win_privs.rb)) |
| post/windows/gather/wmic_command         | 此模块将执行给定的 WMIC 命令选项或从资源文件读取 WMIC 命令选项并执行命令。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/wmic_command.rb)) |
| post/windows/wlan/wlan_profile           | 此模块提取保存的无线 LAN 配置文件。它还将尝试解密网络密钥材料。操作系统版本之间的行为略有不同。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/wlan/wlan_profile.rb)) |

### Windows 权限提升模块

| Metasploit module                        | Description                                                  | Note/Platforms                                               |
| :--------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/escalate/getsystem          | 该模块使用内置的“getsystem”命令将当前会话从管理员用户帐户升级到 SYSTEM 帐户。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/escalate/getsystem.rb)) |
| post/windows/escalate/golden_ticket      | 此模块将使用 Mimikatz Kiwi 扩展创建金 Kerberos 票。如果未应用任何选项，它将尝试识别当前域、域管理员帐户、目标域 SID，并从数据库中检索 krbtgt NTLM 哈希。默认情况下，众所周知的管理员组 512、513、518、519 和 520 将应用于票证。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/escalate/golden_ticket.rb), [ref1](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos)) |
| post/windows/escalate/unmarshal_cmd_exec | 该模块利用本地权限提升漏洞，该漏洞存在于 microsoft COM for windows 中，无法正确处理序列化对象。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/escalate/unmarshal_cmd_exec.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/escalate/unmarshal_cmd_exec.md), [ref1](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0824), [ref2](https://github.com/x73x61x6ex6ax61x79/UnmarshalPwn)) |

### 间谍/捕获 (Windows)

| Metasploit module                    | Description                                                  | Note/Platforms                                               |
| :----------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/capture/keylog_recorder | 该模块可用于捕获键盘记录。建议将此模块作为作业运行，否则会占用您的框架用户界面。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/capture/keylog_recorder.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/capture/keylog_recorder.md)) |
| post/windows/gather/screen_spy       | 此模块将逐步从主机获取桌面屏幕截图。这允许屏幕监视，这对于确定机器上是否有活动用户或记录屏幕以供以后提取数据很有用。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/screen_spy.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/screen_spy.md)) |
| post/windows/manage/rpcapd_start     | 此模块启用 Winpcap 的默认安装中包含的远程数据包捕获系统（rpcapd 服务）。该模块允许您以被动或主动模式设置服务（如果客户端位于防火墙后面，则很有用）。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/rpcapd_start.rb)) |
| post/windows/manage/webcam           | 此模块将允许用户检测已安装的网络摄像头（使用 LIST 操作）或拍摄快照（使用 SNAPSHOT）操作。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/webcam.rb)) |

### 取证 (Windows)

| Metasploit module                            | Description                                                  | Note/Platforms                                               |
| :------------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/gather/dumplinks                | dumplinks 模块是 Harlan Carvey 的 lslnk.pl Perl 脚本的修改端口。此模块将从用户的“最近的文档”文件夹和 Microsoft Office 的“最近的文档”文件夹（如果存在）解析 .lnk 文件。Windows 会自动为许多常见文件类型创建这些链接文件。.lnk 文件包含时间戳、文件位置，包括共享名称、卷序列号等。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/dumplinks.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/dumplinks.md)) |
| post/windows/gather/file_from_raw_ntfs       | 该模块使用原始 NTFS 设备收集文件，绕过一些 Windows 限制，例如使用写锁定打开文件。因为它避免了通常的文件锁定问题，所以它可用于检索诸如 NTDS.dit 之类的文件。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/file_from_raw_ntfs.rb), [ref1](https://www.amazon.com/System-Forensic-Analysis-Brian-Carrier/dp/0321268172/)) |
| post/windows/gather/forensics/recovery_files | 此模块列出并尝试从 NTFS 文件系统中恢复已删除文件。使用 FILES 选项调整恢复过程。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/forensics/recovery_files.rb), [ref1](https://www.youtube.com/watch?v=9yzCf360ujY&hd=1)) |

### 通用 / 其他 (Windows)

| Metasploit module                              | Description                                                  | Note/Platforms                                               |
| :--------------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/manage/killav                     | 此模块尝试定位和终止任何标识为与防病毒或基于主机的 IPS 相关的进程。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/killav.rb)) |
| post/windows/manage/change_password            | 此模块将尝试更改目标帐户的密码。典型用法是更改新创建的帐户的密码。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/change_password.rb)) |
| post/windows/manage/download_exec              | 此模块将通过 railgun 导入 urlmon 来下载文件。用户还可以选择通过 exec_string 使用参数执行文件。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/download_exec.rb)) |
| post/windows/manage/enable_rdp                 | 此模块启用远程桌面服务 (RDP)。它提供了创建帐户并将其配置为本地管理员和远程桌面用户组成员的选项。它还可以转发目标的端口 3389/tcp。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/enable_rdp.rb)) |
| post/windows/manage/execute_dotnet_assembly    | 此模块在内存中执行 .NET 程序集。它反射性地加载一个将承载 CLR 的 dll，然后将要执行的程序集复制到内存中。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/execute_dotnet_assembly.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/manage/execute_dotnet_assembly.md), [ref1](https://b4rtik.blogspot.com/2018/12/execute-assembly-via-meterpreter-session.html)) |
| post/windows/manage/exec_powershell            | 该模块将在一个 Meterpreter 会话中执行一个 powershell 脚本。用户还可以在执行之前输入要在内存中进行的文本替换。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/exec_powershell.rb)) |
| post/windows/manage/hashcarve                  | 此模块将直接在注册表中更改本地用户的密码。                   | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/hashcarve.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/manage/hashcarve.md)) |
| post/windows/manage/inject_ca                  | 该模块允许攻击者将任意 CA 证书插入到受害者的受信任根存储中。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/inject_ca.rb)) |
| post/windows/manage/migrate                    | 此模块将 Meterpreter 会话从一个进程迁移到另一个进程。要迁移到的给定进程 PID，或者模块可以生成一个并迁移到该新生成的进程。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/migrate.rb)) |
| post/windows/manage/peinjector                 | 此模块将指定的 Windows 负载注入目标可执行文件。              | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/peinjector.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/manage/peinjector.md)) |
| post/windows/manage/portproxy                  | 该模块使用来自 netsh 的 PortProxy 接口来持久地设置端口转发（即使在重新启动后）。PortProxy 支持 TCP IPv4 和 IPv6 连接 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/portproxy.rb)) |
| post/windows/manage/powershell/exec_powershell | 此模块将通过 Meterpreter 会话下载和执行 PowerShell 脚本。用户还可以在执行之前输入要在内存中进行的文本替换。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/powershell/exec_powershell.rb)) |
| post/windows/manage/powershell/load_script     | 该模块将通过当前的 powershell 会话下载并执行一个或多个 PowerShell 脚本。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/powershell/load_script.rb)) |
| post/windows/manage/sticky_keys                | 该模块可以将“粘滞键”黑客应用于具有适当权限的会话。hack 提供了一种在 RDP 登录屏幕或通过 UAC 确认对话框使用 UI 级交互获取 SYSTEM shell 的方法。该模块会修改某些可执行文件（sethc.exe、utilman.exe、osk.exe 或 displayswitch.exe）的调试注册表设置。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/sticky_keys.rb), [ref1](https://social.technet.microsoft.com/Forums/windows/en-US/a3968ec9-5824-4bc2-82a2-a37ea88c273a/sticky-keys-exploit), [ref2](http://carnal0wnage.attackresearch.com/2012/04/privilege-escalation-via-sticky-keys.html)) |
| post/windows/manage/vss_create                 | 此模块将尝试创建新的卷影副本。                               | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/vss_create.rb), [ref1](http://pauldotcom.com/2011/11/safely-dumping-hashes-from-liv.html)) |
| post/windows/manage/vss_list                   | 此模块将尝试列出系统上的所有卷影副本。                       | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/vss_list.rb), [ref1](http://pauldotcom.com/2011/11/safely-dumping-hashes-from-liv.html)) |
| post/windows/manage/vss_mount                  | 此模块将尝试在系统上挂载卷影副本。                           | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/vss_mount.rb), [ref1](http://pauldotcom.com/2011/11/safely-dumping-hashes-from-liv.html)) |
| post/windows/manage/vss_set_storage            | 此模块将尝试更改卷影副本存储的空间量。                       | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/vss_set_storage.rb), [ref1](http://pauldotcom.com/2011/11/safely-dumping-hashes-from-liv.html)) |
| post/windows/manage/vss_storage                | 此模块将尝试获取卷影副本存储信息。                           | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/vss_storage.rb), [ref1](http://pauldotcom.com/2011/11/safely-dumping-hashes-from-liv.html)) |

## Active Directory 模块

### 凭据窃取（Active Directory）

| Metasploit module                               | Description                                                  | Note/Platforms                                               |
| :---------------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/gather/credentials/domain_hashdump | 此模块尝试从实时域控制器复制 NTDS.dit 数据库，然后解析所有用户帐户。它保存所有捕获的密码哈希，包括历史哈希。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/domain_hashdump.rb)) |
| post/windows/gather/credentials/gpp             | 该模块枚举受害机器的域控制器并通过 SMB 连接到它。然后查找包含本地用户帐户和密码 (cPassword) 的组策略首选项 XML 文件，并使用公开的 AES 密钥对其进行解密。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb), [ref1](https://msdn.microsoft.com/en-us/library/cc232604(v=prot.13)), [ref2](https://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html), [ref3](http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx), [ref4](https://labs.portcullis.co.uk/blog/are-you-considering-using-microsoft-group-policy-preferences-think-again/)) |
| post/windows/gather/enum_ad_bitlocker           | 此模块将枚举默认 AD 目录中的 BitLocker 恢复密码。此模块确实需要域管理员或其他委派权限。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ad_bitlocker.rb), [ref1](https://technet.microsoft.com/en-us/library/cc771778(v=ws.10).aspx)) |
| post/windows/gather/enum_ad_user_comments       | 此模块将枚举默认 Active Domain (AD) 目录中的用户帐户，默认情况下，这些帐户的描述或注释中包含“pass”（不区分大小写）。在某些情况下，此类用户的密码会在这些字段中指定。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ad_user_comments.rb), [ref1](http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)) |
| post/windows/gather/ntds_grabber                | 该模块使用 powershell 脚本来获取域控制器上的 ntds.dit SAM 和 SYSTEM 文件的副本。它将所有这些文件压缩在一个名为 All.cab 的压缩文件中。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/ntds_grabber.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/ntds_grabber.md)) |
| post/windows/gather/ntds_location               | 该模块将查找 NTDS.DIT 文件的位置（从注册表检查它是否存在，并在屏幕上显示其位置，如果您希望使用 ntdsutil 或对比 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/ntds_location.rb)) |

### 信息收集（Active Directory）

| Metasploit module                                   | Description                                                  | Note/Platforms                                               |
| :-------------------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/gather/bloodhound                      | 该模块将执行 BloodHound C# Ingestor（又名 SharpHound）以收集会话、本地管理员、域信任等。有了这些信息，BloodHound 将能够识别可能导致 Active Directory 环境受损的攻击路径。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/bloodhound.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/bloodhound.md), [ref1](https://github.com/BloodHoundAD/BloodHound/)) |
| post/windows/gather/enum_ad_managedby_groups        | 此模块将枚举指定域上专门管理的 AD 组和管理器列表。这可以在没有域管理员权限的情况下识别权限提升机会或持久性机制。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ad_managedby_groups.rb)) |
| post/windows/gather/enum_ad_service_principal_names | 此模块将枚举默认 AD 目录中的 servicePrincipalName，其中用户是 Domain Admins 组的成员。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ad_service_principal_names.rb), [ref1](https://www.netspi.com/blog/entryid/214/faster-domain-escalation-using-ldap)) |
| post/windows/gather/enum_domain                     | 该模块通过注册表识别主域。使用的注册表值为：HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\DCName。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_domains.rb)) |
| post/windows/gather/enum_domain_tokens              | 此模块将枚举系统上存在的令牌，这些令牌是目标主机所属域的一部分。它还将枚举本地管理员、用户和备份操作员组中的用户以识别域成员。如果进程在域帐户下运行，也将被枚举和检查，在所有检查中，如果它们是机器所属域的域管理组的一部分，则将检查帐户、进程和令牌。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_domain_tokens.rb)) |
| post/windows/gather/enum_domain_users               | 这个模块将枚举所有域计算机并检查目标用户是否在它们上面有会话。还可以列出哪些用户使用该模块登录了哪些计算机。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_domain_users.rb)) |
| post/windows/gather/enum_tokens                     | 此模块将识别具有域管理员（委派）令牌的系统。该模块将首先检查某些操作是否存在足够的权限，然后为系统运行 getprivs。如果您将权限提升到系统，则不会分配 SeAssignPrimaryTokenPrivilege，在这种情况下，请尝试迁移到作为系统运行的另一个进程。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_tokens.rb)) |
| post/windows/gather/local_admin_search_enum         | 此模块将识别给定范围内的系统，提供的域用户（应迁移到用户 pid）对其具有管理访问权限。它使用 Windows OpenSCManagerA API 函数。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb)) |

### 通用/其他（活动目录）

| Metasploit 模块              | 描述                                                         | Note/Platforms                                               |
| :--------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/manage/add_user | 此模块将用户添加到域和/或域组。如果需要，它将检查是否存在足够的权限并为系统运行 getprivs。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/add_user.rb)) |

## Linux 后渗透模块

### 提取凭据 (Linux)

| Metasploit module                      | Description                                                  | Note/Platforms                                               |
| :------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/linux/gather/hashdump             | 转储密码哈希 Post 模块转储 Linux 系统上所有用户的密码哈希。  | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/hashdump.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/linux/gather/hashdump.md)) |
| post/linux/gather/openvpn_credentials  | 该模块从 Linux 上的进程列表中获取 OpenVPN 凭据。注意：–auth-nocache 不得在 OpenVPN 命令行中设置。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/openvpn_credentials.rb), [ref1](https://gist.github.com/rvrsh3ll/cc93a0e05e4f7145c9eb#file-openvpnscraper-sh)) |
| post/linux/gather/phpmyadmin_credsteal | 该模块从目标 linux 机器收集 PhpMyAdmin 凭证。                | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/phpmyadmin_credsteal.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/linux/gather/phpmyadmin_credsteal.md)) |

### 信息收集 (Linux)

| Metasploit module                    | Description                                                  | Note/Platforms                                               |
| :----------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/linux/gather/checkcontainer     | 该模块尝试确定系统是否在容器内运行。它支持检测 Docker、LXC 和 systemd nspawn。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/checkcontainer.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/linux/gather/checkcontainer.md)) |
| post/linux/gather/checkvm            | 该模块尝试确定系统是否在虚拟环境中运行。它支持检测 Hyper-V、VMWare、VirtualBox、Xen 和 QEMU/KVM。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/checkvm.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/linux/gather/checkvm.md)) |
| post/linux/gather/enum_commands      | 该模块将列出目标系统上的可用命令，例如在 /bin/、/usr/bin、/sbin、/usr/sbin 目录等中 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/enum_commands.rb)) |
| post/linux/gather/enum_configs       | 该模块收集常见安装的应用程序和服务的配置文件，例如 Apache、MySQL、Samba、Sendmail 等 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/enum_configs.rb)) |
| post/linux/gather/enum_containers    | 该模块尝试枚举目标机器上的容器，并可选择在每个找到的活动容器上运行命令。目前支持 Docker、LXC 和 RKT。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/enum_containers.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/linux/gather/enum_containers.md)) |
| post/linux/gather/enum_network       | 该模块从目标系统 IPTables 规则、接口、无线信息、开放和侦听端口、活动网络连接、DNS 信息和 SSH 信息收集网络信息。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/enum_network.rb)) |
| post/linux/gather/enum_users_history | 该模块收集以下特定于用户的信息：shell 历史、MySQL 历史、PostgreSQL 历史、MongoDB 历史、Vim 历史、lastlog 和 sudoers。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/gather/enum_users_history.rb)) |

### 通用/其他 (Linux)

| Metasploit module                    | Description                                                  | Note/Platforms                                               |
| :----------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/linux/manage/dns_spoofing       | 该模块会将目标 Linux 系统上的所有 DNS 请求重定向到任意远程 DNS 服务器。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/manage/dns_spoofing.rb)) |
| post/linux/manage/download_exec      | 此模块使用 bash 下载并运行文件。它首先尝试使用 curl 作为其 HTTP 客户端，如果未找到则使用 wget。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/manage/download_exec.rb)) |
| post/linux/manage/sshkey_persistence | 该模块会为指定用户（或所有用户）添加一个 SSH 密钥，以允许随时通过 SSH 进行远程登录。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/linux/manage/sshkey_persistence.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/linux/manage/sshkey_persistence.md)) |

## Mac OS X 后渗透模块

### 提取凭据 (Mac OS X)

| Metasploit module                     | Description                                                  | Note/Platforms                                               |
| :------------------------------------ | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/osx/gather/autologin_password    | 自动登录密码 此模块将窃取机器上启用自动登录的任何用户的明文密码。需要根访问权限。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/autologin_password.rb), [ref1](http://www.brock-family.org/gavin/perl/kcpassword.html)) |
| post/osx/gather/password_prompt_spoof | 向登录的 OSX 用户显示密码提示对话框。                        | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/password_prompt_spoof.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/osx/gather/password_prompt_spoof.md), [ref1](http://blog.packetheader.net/2011/10/fun-with-applescript.html)) |

### 间谍/捕获 (Mac OS X)

| Metasploit module                | Description                                                  | Note/Platforms                                               |
| :------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/osx/capture/keylog_recorder | 记录除 cmd 键和 GUI 密码输入之外的所有键盘事件。键盘日志在客户端/服务器之间每隔 SYNCWAIT 秒以块的形式传输，以确保可靠性。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/capture/keylog_recorder.rb)) |
| post/osx/capture/screen          | 该模块截取目标桌面的屏幕截图并自动下载它们。                 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/capture/screen.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/osx/capture/screen.md)) |
| post/osx/manage/record_mic       | 该模块将允许用户检测（使用 LIST 操作）和捕获（使用 RECORD 操作）远程 OSX 机器上的音频输入。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/manage/record_mic.rb)) |
| post/osx/manage/webcam           | 此模块将允许用户检测已安装的网络摄像头（使用 LIST 操作）、拍摄快照（使用 SNAPSHOT 操作）或录制网络摄像头和麦克风（使用 RECORD 操作）。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/manage/webcam.rb)) |

## 浏览器后渗透模块

### Mozilla Firefox 后渗透模块

| Metasploit module               | Description                                                  | Note/Platforms                                               |
| :------------------------------ | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/firefox/gather/cookies     | 此模块允许从 Firefox Privileged Javascript Shell 收集 cookie。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/firefox/gather/cookies.rb)) |
| post/firefox/gather/history     | 该模块允许从 Firefox Privileged Javascript Shell 收集整个浏览器历史记录。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/firefox/gather/history.rb)) |
| post/firefox/gather/passwords   | 该模块允许从 Firefox Privileged Javascript Shell 收集密码。  | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/firefox/gather/passwords.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/firefox/gather/passwords.md)) |
| post/firefox/manage/webcam_chat | 此模块允许从特权 Firefox Javascript shell 流式传输网络摄像头。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/firefox/manage/webcam_chat.rb), [ref1](http://www.rapid7.com/db/modules/exploit/firefox/local/exec_shellcode)) |
| post/multi/gather/firefox_creds | 此模块将从系统上找到的 Firefox Web 浏览器收集凭据和 cookie。Firefox 将密码存储在 signons.sqlite 数据库文件中。还有一个keys3.db 文件，其中包含解密这些密码的密钥。在未设置主密码的情况下，可以使用参考的第 3 方工具或通过将 DECRYPT 选项设置为 true 来轻松解密密码。 | Platforms: bsd, linux, osx, unix, win ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/firefox_creds.rb), [ref1](https://github.com/Unode/firefox_decrypt), [ref2](https://github.com/philsmd/pswRecovery4Moz)) |

### Google Chrome 后渗透模块

| Metasploit module                | Description                                               | Note/Platforms                                               |
| :------------------------------- | :-------------------------------------------------------- | ------------------------------------------------------------ |
| post/multi/gather/chrome_cookies | 从目标用户的默认 Chrome 配置文件中读取所有 cookie。       | Platforms: linux, unix, bsd, osx, windows ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/chrome_cookies.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/chrome_cookies.md)) |
| post/windows/gather/enum_chrome  | 此模块将从 Google Chrome 收集用户数据并尝试解密敏感信息。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_chrome.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/enum_chrome.md)) |

### Internet Explorer 后渗透模块

| Metasploit module               | Description                                                  | Note/Platforms                                               |
| :------------------------------ | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/windows/gather/enum_ie     | 此模块将收集**[Internet Explorer 中的](https://www.infosecmatter.com/metasploit-module-library/?mm=post/windows/gather/enum_ie)**历史记录、cookie 和凭据（来自 HTTP 身份验证密码，或在自动完成中找到的已保存表单密码）。仅 IE ≥7 版本支持收集凭据的功能，而所有版本都可以提取历史记录和 cookie。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ie.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/enum_ie.md)) |
| post/windows/manage/ie_proxypac | 此模块将 Internet Explorer 配置为使用 PAC 代理文件。通过使用 LOCAL_PAC 选项，将在受害主机上创建 PAC 文件。也可以通过提供完整的 URL 来提供远程 PAC 文件（REMOTE_PAC 选项）。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/ie_proxypac.rb), [ref1](https://www.youtube.com/watch?v=YGjIlbBVDqE&hd=1), [ref2](http://blog.scriptmonkey.eu/bypassing-group-policy-using-the-windows-registry)) |

## 移动设备后渗透模块

### Android 后渗透模块

| Metasploit module                    | Description                                                  | Note/Platforms                                               |
| :----------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/android/capture/screen          | 该模块对目标手机显示屏幕进行截图。                           | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/capture/screen.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/android/capture/screen.md)) |
| post/android/gather/hashdump         | Post 模块转储 Android 系统的密码哈希。ROOT是必需的。         | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/gather/hashdump.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/android/gather/hashdump.md), [ref1](https://www.pentestpartners.com/security-blog/cracking-android-passwords-a-how-to/), [ref2](https://hashcat.net/forum/thread-2202.html)) |
| post/android/gather/sub_info         | **[Extracts subscriber info from target device](https://www.infosecmatter.com/metasploit-module-library/?mm=post/android/gather/sub_info)** This module displays the subscriber info stored on the target phone. It uses call service to get values of each transaction code like imei etc. ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/gather/sub_info.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/android/gather/sub_info.md)) |                                                              |
| post/android/gather/wireless_ap      | 此模块显示保存在目标设备上的所有无线 AP 凭据。               | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/gather/wireless_ap.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/android/gather/wireless_ap.md)) |
| post/android/manage/remove_lock      | 该模块利用了 Android 4.0 到 4.3 com.android.settings.ChooseLockGeneric 类中的一个错误。任何非特权应用程序都可以利用此漏洞移除锁屏，设备将通过滑动解锁。此漏洞已在 Android 4.4 中修补。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/manage/remove_lock.rb), [ref1](http://blog.curesec.com/article/blog/26.html), [ref2](http://www.curesec.com/data/advisories/Curesec-2013-1011.pdf)) |
| post/android/manage/remove_lock_root | 该模块使用root权限来移除设备锁。在某些情况下，原始锁定方法仍将存在，但任何键/手势都将解锁设备。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/manage/remove_lock_root.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/android/manage/remove_lock_root.md)) |

### Apple iOS 后渗透模块

| Metasploit module                      | Description                                                  | Note/Platforms                                               |
| :------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| post/apple_ios/gather/ios_image_gather | 该模块从 iPhone 收集图像。模块在 iPhone 5 上的 iOS 10.3.3 上进行了测试。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/apple_ios/gather/ios_image_gather.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/apple_ios/gather/ios_image_gather.md)) |
| post/apple_ios/gather/ios_text_gather  | 该模块从 iPhone 收集短信。在 iPhone 5 上的 iOS 10.3.3 上测试。 | ([source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/apple_ios/gather/ios_text_gather.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/apple_ios/gather/ios_text_gather.md)) |

## References

[InfoSec](https://www.infosecmatter.com/post-exploitation-metasploit-modules-reference/)

[MetaSploit](https://github.com/rapid7/metasploit-framework/)

