import "pe"

rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_2
{
	meta:
		description = "Detects malicious VEILEDSIGNAL backdoor"
		author = "X__Junior"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/xtrader-3cx-supply-chain"
		date = "2023-04-29"
		hash = "c4887a5cd6d98e273ba6e9ea3c1d8f770ef26239819ea24a1bfebd81d6870505"
		score = 80
		os = "windows"
		filetype = "executable"

	strings:
		$sa1 = "\\.\\pipe\\gecko.nativeMessaging" ascii
		$sa2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/95.0.1020.40" ascii
		$sa3 = "application/json, text/javascript, */*; q=0.01" ascii
		$op1 = { 89 7? 24 ?? 44 8B CD 4C 8B C? 48 89 44 24 ?? 33 D2 33 C9 FF 15}
		$op2 = { 4C 8B CB 4C 89 74 24 ?? 4C 8D 05 ?? ?? ?? ?? 44 89 74 24 ?? 33 D2 33 C9 FF 15}
		$op3 = { 48 89 74 24 ?? 45 33 C0 89 74 24 ?? 41 B9 ?? ?? ?? ?? 89 74 24 ?? 48 8B D8 48 C7 00 ?? ?? ?? ?? 48 8B 0F 41 8D 50 ?? 48 89 44 24 ?? 89 74 24 ?? FF 15}

	condition:
		all of ($op*) or all of ($sa*)
}
