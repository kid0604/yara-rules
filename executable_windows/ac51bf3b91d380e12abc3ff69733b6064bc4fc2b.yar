import "pe"

rule MALWARE_Win_IPsecHelper
{
	meta:
		author = "ditekSHen"
		description = "Detects IPsecHelper backdoor"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "rundll32.exe advapi32.dll,ProcessIdleTasks" wide
		$s2 = "CommandExecute" fullword ascii
		$s3 = "DownloadExecuteUrl" fullword ascii
		$s4 = "DownloadExecuteFile" fullword ascii
		$s5 = "CmdExecute" fullword ascii
		$s6 = "ExecuteProcessWithResult" fullword ascii
		$s7 = "IsFirstInstance ==> checked" fullword wide
		$s8 = "del \"%PROG%%SERVICENAME%\".*" fullword wide
		$s9 = ".CreateConfig" wide
		$s10 = ".SelfDelete" wide
		$c1 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; EmbeddedWB 14.52 from: http://www.google.com/ EmbeddedWB 14.52;" wide
		$c2 = "boot.php" wide
		$c3 = "lastupdate.php" wide
		$c4 = "main.php" wide
		$c5 = "InternetNeeded" wide
		$c6 = "DeviceIdSalt" wide

	condition:
		uint16(0)==0x5a4d and (6 of ($s*) or 4 of ($c*) or 8 of them )
}
