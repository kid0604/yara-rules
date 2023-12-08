rule HKTL_NET_AdCollector_Sep22_1
{
	meta:
		description = "Detects ADCollector Tool - a lightweight tool to quickly extract valuable information from the Active Directory environment for both attacking and defending"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/dev-2null/ADCollector"
		date = "2022-09-15"
		score = 75
		hash1 = "241390219a0a773463601ca68b77af97453c20af00a66492a7a78c04d481d338"
		hash2 = "cc086eb7316e68661e3d547b414890d5029c5cc460134d8b628f4b0be7f27fb3"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "ADCollector.exe --SPNs --Term key --Acls 'CN=Domain Admins,CN=Users,DC=lab,DC=local'" wide fullword
		$s1 = "ADCollector.exe" wide fullword
		$s2 = "ENCRYPTED_TEXT_PASSWORD_ALLOWED" ascii fullword
		$s3 = "\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf" wide
		$s4 = "[-] Password Does Not Expire Accounts:" wide
		$s5 = "  * runAs:       {0}" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (1 of ($x*) or 3 of them )
}
