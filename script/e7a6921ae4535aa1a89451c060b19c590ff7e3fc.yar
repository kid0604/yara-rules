rule EXPL_LOG_ProxyNotShell_PowerShell_Proxy_Log_Dec22_1
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		date = "2022-12-22"
		modified = "2023-01-26"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$re1 = /,\/[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll][^\n]{0,50},Kerberos,true,[^\n]{0,50},200,0,,,,[^\n]{0,2000};OnEndRequest\.End\.ContentType=application\/soap\+xml charset UTF-8;S:ServiceCommonMetadata\.HttpMethod=POST;/ ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		$re1 and not 1 of ($fp*)
}
