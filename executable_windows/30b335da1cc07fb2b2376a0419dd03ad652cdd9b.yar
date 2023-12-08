rule Windows_Trojan_Clipbanker_7efaef9f
{
	meta:
		author = "Elastic Security"
		id = "7efaef9f-51cd-4fea-a48d-fa9d39cb735e"
		fingerprint = "fe0ec44f8707cd03f845dbea4ff5bb1b699db1b69b75f0365168a75cc8bb68a3"
		creation_date = "2022-02-28"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Clipbanker"
		reference_sample = "02b06acb113c31f5a2ac9c99f9614e0fab0f78afc5ae872e46bae139c2c9b1f6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Clipbanker"
		filetype = "executable"

	strings:
		$a1 = "C:\\Users\\youar\\Desktop\\Allcome\\Source code\\Build\\Release\\Build.pdb" ascii fullword
		$b1 = "https://steamcommunity.com/tradeoffer" ascii fullword
		$b2 = "/Create /tn NvTmRep_CrashReport3_{B2FE1952-0186} /sc MINUTE /tr %s" ascii fullword
		$b3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" ascii fullword
		$b4 = "ProcessHacker.exe" ascii fullword

	condition:
		all of them
}
