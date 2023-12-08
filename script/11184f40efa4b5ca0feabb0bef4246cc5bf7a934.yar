rule EXPL_LOG_ProxyNotShell_OWASSRF_PowerShell_Proxy_Log_Dec22_1
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		date = "2022-12-22"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "/owa/mastermailbox%40outlook.com/powershell" ascii wide
		$sa1 = " 200 " ascii wide
		$sa2 = " POST " ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		all of ($s*) and not 1 of ($fp*)
}
