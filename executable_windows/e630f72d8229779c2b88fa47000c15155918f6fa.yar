import "pe"

rule APT_MAL_NK_3CX_ICONIC_Stealer_Mar23_1
{
	meta:
		description = "Detects ICONIC stealer payload used in the 3CX incident"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/volexity/threat-intel/blob/main/2023/2023-03-30%203CX/attachments/iconicstealer.7z"
		date = "2023-03-31"
		score = 80
		hash1 = "8ab3a5eaaf8c296080fadf56b265194681d7da5da7c02562953a4cb60e147423"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "{\"HostName\": \"%s\", \"DomainName\": \"%s\", \"OsVersion\": \"%d.%d.%d\"}" wide fullword
		$s2 = "******************************** %s ******************************" wide fullword
		$s3 = "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data" wide fullword
		$s4 = "AppData\\Roaming\\Mozilla\\Firefox\\Profiles" wide fullword
		$s5 = "SELECT url, title FROM urls ORDER BY id DESC LIMIT 500" wide fullword
		$s6 = "TEXT value in %s.%s" ascii fullword
		$op1 = { 48 63 d1 48 63 ce 49 03 d1 49 03 cd 4c 63 c7 e8 87 1f 09 00 8b 45 d0 44 8d 04 37 }
		$op2 = { 48 8b c8 8b 56 f0 48 89 46 d8 e8 78 8f f8 ff e9 ec 13 00 00 c7 46 20 ff ff ff ff e9 e0 13 00 00 33 ff }

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and 4 of them or 6 of them
}
