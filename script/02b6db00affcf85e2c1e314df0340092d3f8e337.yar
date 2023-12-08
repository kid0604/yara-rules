rule EXPL_LOG_ProxyNotShell_OWASSRF_PowerShell_Proxy_Log_Dec22_3
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		date = "2022-12-22"
		score = 60
		os = "windows"
		filetype = "script"

	strings:
		$sa1 = " POST /powershell - 444 " ascii wide
		$sa2 = " POST /Powershell - 444 " ascii wide
		$sb1 = " - 200 0 0 2" ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		1 of ($sa*) and $sb1 and not 1 of ($fp*)
}
