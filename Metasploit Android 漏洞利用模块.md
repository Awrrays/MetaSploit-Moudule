# Metasploit Android 漏洞利用模块

总共有 52 个 Metasploit 模块，要么直接用于 Android 设备（例如`exploit/android/..`），要么间接影响 Android 平台，因为它们支持 Android 操作系统或 Dalvik 架构（例如`exploit/multi/..`）。

以下是可在 Android 设备上使用的所有 Metasploit 模块的细分：

- 8 个漏洞利用和 9 个有效载荷
- 7个提权漏洞
- 12 个后期开发模块
- 16个辅助模块

[Hacking an android device with MSFvenom [updated 2020]](https://resources.infosecinstitute.com/topic/lab-hacking-an-android-device-with-msfvenom/)

## Android Metasploit 漏洞利用

- [exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection.rb)
- [exploit/android/fileformat/adobe_reader_pdf_js_interface](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/fileformat/adobe_reader_pdf_js_interface.rb)
- [exploit/android/browser/stagefright_mp4_tx3g_64bit](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/browser/stagefright_mp4_tx3g_64bit.rb)
- [exploit/android/browser/samsung_knox_smdm_url](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/browser/samsung_knox_smdm_url.rb)
- [exploit/android/adb/adb_server_exec](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/adb/adb_server_exec.rb)
- [exploit/multi/hams/steamed](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/hams/steamed.rb)
- [exploit/android/local/janus](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/local/janus.rb)
- [exploit/multi/handler](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/handler.rb)

| Metasploit Module                                            | Date       | Rank      | Details                                                      |
| :----------------------------------------------------------- | :--------- | :-------- | :----------------------------------------------------------- |
| exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection | 2020-10-29 | excellent | 当使用精心制作的 APK 文件作为 Android 负载模板时，该模块利用 Metasploit Framework 的 msfvenom 负载生成器中的命令注入漏洞。影响的Metasploit框架...**Platforms**: unix **CVEs**: [CVE-2020-7384](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7384) **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection.rb), [ref1](https://github.com/justinsteven/advisories/blob/master/2020_metasploit_msfvenom_apk_template_cmdi.md) |
| exploit/android/adb/adb_server_exec                          | 2016-01-01 | excellent | 在侦听 adb 调试消息的 android 设备上写入并生成本机负载。**Platforms**: linux **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/adb/adb_server_exec.rb) |
| exploit/android/local/janus                                  | 2017-07-31 | manual    | 该模块利用 Android 中的 CVE-2017-13156 将有效负载安装到另一个应用程序中。有效载荷APK将具有相同的签名，可以安装作为更新，保留现有... **Platforms**: android **CVEs**: [CVE-2017-13156](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13156) **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/local/janus.rb), [ref1](https://www.guardsquare.com/en/blog/new-android-vulnerability-allows-attackers-modify-apps-without-affecting-their-signatures), [ref2](https://github.com/V-E-O/PoC/tree/master/CVE-2017-13156) |
| exploit/multi/handler                                        | -          | manual    | 该模块是一个存根，它为在框架外启动的漏洞利用提供 Metasploit 有效载荷系统的所有功能。 **Platforms**: android, apple_ios, bsd, java, js, linux, mainframe, multi, nodejs, osx, php, python, ruby, solaris, unix, win **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/handler.rb) |

## Android Metasploit 提权漏洞

- [exploit/android/browser/webview_addjavascriptinterface](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/browser/webview_addjavascriptinterface.rb)
- [post/multi/recon/local_exploit_suggester](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/recon/local_exploit_suggester.rb)
- [exploit/multi/local/allwinner_backdoor](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/local/allwinner_backdoor.rb)
- [exploit/android/local/put_user_vroot](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/local/put_user_vroot.rb)
- [exploit/android/local/futex_requeue](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/local/futex_requeue.rb)
- [exploit/android/local/binder_uaf](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/local/binder_uaf.rb)
- [exploit/android/local/su_exec](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/local/su_exec.rb)

| Metasploit Module                        | Date       | Rank      | Details                                                      |
| :--------------------------------------- | :--------- | :-------- | :----------------------------------------------------------- |
| post/multi/recon/local_exploit_suggester | -          | normal    | 该模块建议可以使用的本地 Meterpreter 漏洞利用。漏洞利用是根据用户打开的 shell 的架构和平台以及可用漏洞来建议的……**Platforms**: all **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/recon/local_exploit_suggester.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/recon/local_exploit_suggester.md) |
| exploit/android/local/binder_uaf         | 2019-09-26 | excellent | 该模块利用了 CVE-2019-2215，这是 Android 内核中 Binder 中的 use-after-free。该漏洞是一个本地提权漏洞，允许完全破坏易受攻击的...**Platforms**: android, linux **CVEs**: [CVE-2019-2215](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2215) **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/local/binder_uaf.rb), [ref1](https://bugs.chromium.org/p/project-zero/issues/detail?id=1942), [ref2](https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html), [ref3](https://hernan.de/blog/2019/10/15/tailoring-cve-2019-2215-to-achieve-root/), [ref4](https://github.com/grant-h/qu1ckr00t/blob/master/native/poc.c) |
| exploit/android/local/su_exec            | 2017-08-31 | manual    | 该模块使用 root 设备上的 su 二进制文件以 root 身份运行有效负载。有根的 Android 设备将包含一个 su 二进制文件（通常与应用程序链接），允许用户运行... **Platforms**: android, linux **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/android/local/su_exec.rb) |

## Android 的 Metasploit Payload

- [payload/android/meterpreter_reverse_https](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/android/meterpreter_reverse_https.rb)
- [payload/android/meterpreter/reverse_https](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_https.rb)
- [payload/android/meterpreter_reverse_http](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/android/meterpreter_reverse_http.rb)
- [payload/android/meterpreter/reverse_http](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_http.rb)
- [payload/android/meterpreter_reverse_tcp](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/android/meterpreter_reverse_tcp.rb)
- [payload/android/meterpreter/reverse_tcp](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_tcp.rb)
- [payload/android/shell/reverse_https](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_https.rb)
- [payload/android/shell/reverse_http](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_http.rb)
- [payload/android/shell/reverse_tcp](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_tcp.rb)

| Metasploit Payload                        | Size  | Details                                                      |
| :---------------------------------------- | :---- | :----------------------------------------------------------- |
| payload/android/meterpreter/reverse_http  | 10405 | 在 Android 中运行一个 Meterpreter 服务器。通过 HTTP 进行隧道通信。 **Platforms**: android **Archs**: dalvik **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_http.rb) |
| payload/android/meterpreter_reverse_http  | 79840 | 连接回攻击者并生成一个 Meterpreter shell。**Platforms**: android **Archs**: dalvik **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/android/meterpreter_reverse_http.rb) |
| payload/android/meterpreter/reverse_https | 10391 | 在 Android 中运行一个 Meterpreter 服务器。通过 HTTPS 进行隧道通信。 **Platforms**: android **Archs**: dalvik **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_https.rb) |
| payload/android/meterpreter_reverse_https | 79789 | 连接回攻击者并生成一个 Meterpreter shell。**Platforms**: android **Archs**: dalvik **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/android/meterpreter_reverse_https.rb) |
| payload/android/meterpreter/reverse_tcp   | 10173 | 在 Android 中运行一个 Meterpreter 服务器。连接后台程序。**Platforms**: android **Archs**: dalvik **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_tcp.rb) |
| payload/android/meterpreter_reverse_tcp   | 79571 | 连接回攻击者并生成一个 Meterpreter shell。**Platforms**: android **Archs**: dalvik **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/android/meterpreter_reverse_tcp.rb) |
| payload/android/shell/reverse_http        | 10439 | 生成一个管道命令外壳 (sh)。通过 HTTP 进行隧道通信。**Platforms**: android **Archs**: dalvik **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_http.rb) |
| payload/android/shell/reverse_https       | 10288 | 生成一个管道命令外壳 (sh)。通过 HTTPS 进行隧道通信。**Platforms**: android **Archs**: dalvik **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_https.rb) |
| payload/android/shell/reverse_tcp         | 10156 | 生成一个管道命令外壳 (sh)。连接后台程序。**Platforms**: android **Archs**: dalvik **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/android/reverse_tcp.rb) |

## Android 的 Metasploit 后渗透模块

- [post/multi/gather/enum_software_versions](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/enum_software_versions.rb)
- [post/android/manage/remove_lock_root](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/manage/remove_lock_root.rb)
- [post/android/manage/remove_lock](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/manage/remove_lock.rb)
- [post/multi/gather/wlan_geolocate](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/wlan_geolocate.rb)
- [post/multi/manage/set_wallpaper](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/set_wallpaper.rb)
- [post/multi/manage/play_youtube](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/play_youtube.rb)
- [post/android/gather/wireless_ap](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/gather/wireless_ap.rb)
- [post/android/gather/hashdump](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/gather/hashdump.rb)
- [post/multi/manage/autoroute](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/autoroute.rb)
- [post/android/gather/sub_info](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/gather/sub_info.rb)
- [post/android/capture/screen](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/capture/screen.rb)
- [post/android/local/koffee](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/local/koffee.rb)

| Metasploit Module                        | Date | Details                                                      |
| :--------------------------------------- | :--- | :----------------------------------------------------------- |
| post/multi/gather/enum_software_versions | -    | 该模块在针对受感染机器运行时，将收集所有已安装软件的详细信息，包括它们的版本以及安装时间（如果可用），并将其保存到战利品中...**Platforms**: android, bsd, linux, osx, solaris, win **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/enum_software_versions.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/enum_software_versions.md) |
| post/android/manage/remove_lock_root     | -    | 该模块使用 root 权限来移除设备锁。在某些情况下，原始锁定方法仍将存在，但任何键/手势都将解锁设备。 **Platforms**: android **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/manage/remove_lock_root.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/android/manage/remove_lock_root.md) |
| post/multi/gather/wlan_geolocate         | -    | 枚举目标设备可见的无线网络。（可选）通过收集本地无线网络并针对 Google API 执行查找来对目标进行地理定位。**Platforms**: android, bsd, linux, osx, solaris, win **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/gather/wlan_geolocate.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/wlan_geolocate.md) |
| post/android/gather/wireless_ap          | -    | 此模块显示保存在目标设备上的所有无线 AP 凭据。 **Platforms**: android **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/gather/wireless_ap.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/android/gather/wireless_ap.md) |
| post/multi/manage/set_wallpaper          | -    | 此模块将在指定会话上设置桌面壁纸背景。设置壁纸的方法取决于平台类型。 **Platforms**: android, linux, osx, win **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/set_wallpaper.rb) |
| post/multi/manage/play_youtube           | -    | 该模块将在指定的受感染系统上播放 YouTube 视频。它将在目标机器的本机浏览器中播放视频。VID 数据存储选项是 YouTube 中的“v”参数...**Platforms**: android, linux, osx, unix, win **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/play_youtube.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/manage/play_youtube.md) |
| post/android/gather/hashdump             | -    | Post 模块转储 Android 系统的密码哈希。根是必需的。要执行此操作，需要做两件事。首先，需要password.key文件，因为这包含了散列值，但没有...**Platforms**: android **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/gather/hashdump.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/android/gather/hashdump.md), [ref1](https://www.pentestpartners.com/security-blog/cracking-android-passwords-a-how-to/), [ref2](https://hashcat.net/forum/thread-2202.html) |
| post/android/gather/sub_info             | -    | 此模块显示存储在目标电话上的用户信息。它使用调用服务来获取每个事务代码的值，如 imei 等. **Platforms**: android **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/gather/sub_info.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/android/gather/sub_info.md) |
| post/android/capture/screen              | -    | 该模块截取目标手机的屏幕截图。 **Platforms**: android **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/android/capture/screen.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/android/capture/screen.md) |
| post/multi/manage/autoroute              | -    | 该模块通过现有的 Meterpreter 会话管理会话路由。当连接到指定的 NETWORK 和 SUBMASK 时，它使其他模块能够通过受感染的主机“旋转”。Autoadd 将...**Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/manage/autoroute.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/manage/autoroute.md) |

## Android Metasploit 辅助模块

- [auxiliary/admin/android/google_play_store_uxss_xframe_rce](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/android/google_play_store_uxss_xframe_rce.rb)
- [auxiliary/gather/android_browser_new_tab_cookie_theft](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/android_browser_new_tab_cookie_theft.rb)
- [auxiliary/dos/android/android_stock_browser_iframe](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/dos/android/android_stock_browser_iframe.rb)
- [auxiliary/gather/android_object_tag_webview_uxss](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/android_object_tag_webview_uxss.rb)
- [auxiliary/scanner/http/es_file_explorer_open_port](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/http/es_file_explorer_open_port.rb)
- [auxiliary/server/android_browsable_msf_launch](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/server/android_browsable_msf_launch.rb)
- [auxiliary/gather/samsung_browser_sop_bypass](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/samsung_browser_sop_bypass.rb)
- [auxiliary/gather/android_stock_browser_uxss](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/android_stock_browser_uxss.rb)
- [auxiliary/gather/android_browser_file_theft](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/android_browser_file_theft.rb)
- [auxiliary/server/android_mercury_parseuri](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/server/android_mercury_parseuri.rb)
- [auxiliary/gather/android_htmlfileprovider](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/android_htmlfileprovider.rb)
- [auxiliary/scanner/sip/sipdroid_ext_enum](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/sip/sipdroid_ext_enum.rb)
- [auxiliary/gather/firefox_pdfjs_file_theft](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/firefox_pdfjs_file_theft.rb)
- [auxiliary/server/browser_autopwn2](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/server/browser_autopwn2.rb)
- [auxiliary/server/browser_autopwn](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/server/browser_autopwn.rb)
- [auxiliary/analyze/crack_mobile](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/crack_mobile.rb)

| Metasploit Module                                            | Date       | Details                                                      |
| :----------------------------------------------------------- | :--------- | :----------------------------------------------------------- |
| auxiliary/scanner/http/es_file_explorer_open_port | 2019-01-16 | 该模块连接到 ES File Explorer 的 HTTP 服务器以运行某些命令。HTTP 服务器在应用程序启动时启动，只要应用程序打开就可用。4.1.9.7.4 及以下版本是 ...**CVEs**: [CVE-2019-6447](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6447) **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/http/es_file_explorer_open_port.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/scanner/http/es_file_explorer_open_port.md), [ref1](https://www.ms509.com/2016/03/01/es-explorer-vul/), [ref2](https://github.com/fs0c131y/ESFileExplorerOpenPortVuln), [ref3](https://twitter.com/fs0c131y/status/1085460755313508352) |
| auxiliary/server/android_browsable_msf_launch | -          | 这个模块允许你通过浏览器打开一个 android meterpreter。为了使用它，必须事先在目标设备上安装一个 Android Meterpreter 作为应用程序。为获得最佳结果，... **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/server/android_browsable_msf_launch.rb), [ref1](https://developer.android.com/reference/android/content/Intent.html#CATEGORY_BROWSABLE) |
| auxiliary/gather/android_htmlfileprovider         | -          | 该模块利用 Android 网络浏览器中的跨域问题从易受攻击的设备中窃取文件。 **CVEs**: [CVE-2010-4804](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-4804) **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/android_htmlfileprovider.rb), [ref1](http://thomascannon.net/blog/2010/11/android-data-stealing-vulnerability/) |
| auxiliary/server/browser_autopwn2 | 2015-07-05 | 该模块将自动提供浏览器漏洞利用服务。以下是您可以配置的选项： INCLUDE_PATTERN 选项允许您指定要加载的漏洞利用类型。例如，如果您...**Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/server/browser_autopwn2.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/server/browser_autopwn2.md), [ref1](https://blog.rapid7.com/2015/07/16/the-new-metasploit-browser-autopwn-strikes-faster-and-smarter--part-2) |
| auxiliary/analyze/crack_mobile | -          | 该模块使用 Hashcat 来识别从 Android 系统获取的弱密码。这些使用 MD5 或 SHA1 散列。Android (Samsung) SHA1 是 Hashcat 中的 5800 格式。Android ... **Refs**: [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/analyze/crack_mobile.rb), [docs](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/analyze/crack_mobile.md) |

## Android Meterpreter 命令

```ruby
meterpreter > help

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel
    detach                    Detach the meterpreter session (for http/https)
    disable_unicode_encoding  Disables encoding of unicode strings
    enable_unicode_encoding   Enables encoding of unicode strings
    exit                      Terminate the meterpreter session
    get_timeouts              Get the current session timeout values
    guid                      Get the session GUID
    help                      Help menu
    info                      Displays information about a Post module
    irb                       Open an interactive Ruby shell on the current session
    load                      Load one or more meterpreter extensions
    machine_id                Get the MSF ID of the machine attached to the session
    pry                       Open the Pry debugger on the current session
    quit                      Terminate the meterpreter session
    read                      Reads data from a channel
    resource                  Run the commands stored in a file
    run                       Executes a meterpreter script or Post module
    secure                    (Re)Negotiate TLV packet encryption on the session
    sessions                  Quickly switch to another session
    set_timeouts              Set the current session timeout values
    sleep                     Force Meterpreter to go quiet, then re-establish session
    transport                 Manage the transport mechanisms
    use                       Deprecated alias for "load"
    uuid                      Get the UUID for the current session
    write                     Writes data to a channel


Stdapi: File system Commands
============================

    Command       Description
    -------       -----------
    cat           Read the contents of a file to the screen
    cd            Change directory
    checksum      Retrieve the checksum of a file
    cp            Copy source to destination
    del           Delete the specified file
    dir           List files (alias for ls)
    download      Download a file or directory
    edit          Edit a file
    getlwd        Print local working directory
    getwd         Print working directory
    lcd           Change local working directory
    lls           List local files
    lpwd          Print local working directory
    ls            List files
    mkdir         Make directory
    mv            Move source to destination
    pwd           Print working directory
    rm            Delete the specified file
    rmdir         Remove directory
    search        Search for files
    upload        Upload a file or directory


Stdapi: Networking Commands
===========================

    Command       Description
    -------       -----------
    ifconfig      Display interfaces
    ipconfig      Display interfaces
    portfwd       Forward a local port to a remote service
    route         View and modify the routing table


Stdapi: System Commands
=======================

    Command       Description
    -------       -----------
    execute       Execute a command
    getenv        Get one or more environment variable values
    getuid        Get the user that the server is running as
    localtime     Displays the target system local date and time
    pgrep         Filter processes by name
    ps            List running processes
    shell         Drop into a system command shell
    sysinfo       Gets information about the remote system, such as OS


Stdapi: User interface Commands
===============================

    Command       Description
    -------       -----------
    screenshare   Watch the remote user desktop in real time
    screenshot    Grab a screenshot of the interactive desktop


Stdapi: Webcam Commands
=======================

    Command        Description
    -------        -----------
    record_mic     Record audio from the default microphone for X seconds
    webcam_chat    Start a video chat
    webcam_list    List webcams
    webcam_snap    Take a snapshot from the specified webcam
    webcam_stream  Play a video stream from the specified webcam


Stdapi: Audio Output Commands
=============================

    Command       Description
    -------       -----------
    play          play a waveform audio file (.wav) on the target system


Android Commands
================

    Command           Description
    -------           -----------
    activity_start    Start an Android activity from a Uri string
    check_root        Check if device is rooted
    dump_calllog      Get call log
    dump_contacts     Get contacts list
    dump_sms          Get sms messages
    geolocate         Get current lat-long using geolocation
    hide_app_icon     Hide the app icon from the launcher
    interval_collect  Manage interval collection capabilities
    send_sms          Sends SMS from target session
    set_audio_mode    Set Ringer Mode
    sqlite_query      Query a SQLite database from storage
    wakelock          Enable/Disable Wakelock
    wlan_geolocate    Get current lat-long using WLAN information


Application Controller Commands
===============================

    Command        Description
    -------        -----------
    app_install    Request to install apk file
    app_list       List installed apps in the device
    app_run        Start Main Activty for package name
    app_uninstall  Request to uninstall application

meterpreter > 
```



