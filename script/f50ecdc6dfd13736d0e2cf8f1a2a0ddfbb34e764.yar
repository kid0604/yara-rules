rule LOG_EXPL_ProxyToken_Exploitation_Aug21_1
{
	meta:
		description = "Detects ProxyToken CVE-2021-33766 exploitation attempts on an unpatched system"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.zerodayinitiative.com/blog/2021/8/30/proxytoken-an-authentication-bypass-in-microsoft-exchange-server"
		date = "2021-08-30"
		score = 75
		os = "windows,linux"
		filetype = "script"

	strings:
		$ss0 = "POST " ascii
		$ss1 = " 500 0 0"
		$sa1 = "/ecp/" ascii
		$sa2 = "/RulesEditor/InboxRules.svc/NewObject" ascii
		$sb1 = "/ecp/" ascii
		$sb2 = "SecurityToken=" ascii

	condition:
		all of ($ss*) and ( all of ($sa*) or all of ($sb*))
}
