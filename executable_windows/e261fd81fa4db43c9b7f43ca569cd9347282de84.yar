rule Windows_Trojan_SuddenIcon_99487621
{
	meta:
		author = "Elastic Security"
		id = "99487621-88c4-40f6-918a-f1276cc2d2a7"
		fingerprint = "b16f7de530ed27c42bffec4bcfc1232bad34cdaf4e7a9803fce0564e12701ef1"
		creation_date = "2023-03-29"
		last_modified = "2023-03-30"
		threat_name = "Windows.Trojan.SuddenIcon"
		reference_sample = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan SuddenIcon"
		filetype = "executable"

	strings:
		$str1 = "https://raw.githubusercontent.com/IconStorages/images/main/icon%d.ico" wide fullword
		$str2 = "__tutma" ascii fullword
		$str3 = "__tutmc" ascii fullword
		$str4 = "%s: %s" ascii fullword
		$str5 = "%s=%s" ascii fullword
		$seq_obf = { C1 E1 ?? 33 C1 45 8B CA 8B C8 C1 E9 ?? 33 C1 81 C2 ?? ?? ?? ?? 8B C8 C1 E1 ?? 33 C1 41 8B C8 }
		$seq_virtualprotect = { FF 15 ?? ?? ?? ?? 85 C0 74 ?? FF D5 48 85 C0 74 ?? 81 7B ?? CA 7D 0F 00 75 ?? 48 8D 54 24 ?? 48 8D 4C 24 ?? FF D0 8B F8 44 8B 44 24 ?? 4C 8D 4C 24 ?? BA 00 10 00 00 48 8B CD FF 15 ?? ?? ?? ?? }

	condition:
		5 of ($str*) or 2 of ($seq*)
}
