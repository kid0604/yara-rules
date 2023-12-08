import "pe"

rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_3
{
	meta:
		description = "Detects malicious VEILEDSIGNAL backdoor"
		author = "X__Junior"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/xtrader-3cx-supply-chain"
		date = "2023-04-29"
		hash = "595392959b609caf088d027a23443cf2fefd043607ccdec3de19ad3bb43a74b1"
		score = 80
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 4C 8B CB 4C 89 74 24 ?? 4C 8D 05 ?? ?? ?? ?? 44 89 74 24 ?? 33 D2 33 C9 FF 15}
		$op2 = { 89 7? 24 ?? 44 8B CD 4C 8B C? 48 89 44 24 ?? 33 D2 33 C9 FF 15}
		$op3 = { 8B 54 24 ?? 4C 8D 4C 24 ?? 45 8D 46 ?? 44 89 74 24 ?? 48 8B CB FF 15}
		$op4 = { 48 8D 44 24 ?? 45 33 C9 41 B8 01 00 00 40 48 89 44 24 ?? 41 8B D5 48 8B CF FF 15}

	condition:
		all of them
}
