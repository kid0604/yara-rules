rule Windows_Trojan_Xeno_89f9f060
{
	meta:
		author = "Elastic Security"
		id = "89f9f060-afc8-427d-ad36-3672016efdf6"
		fingerprint = "ddc5bf8c6d5140cb9ea2fbd9b6f1aaab60f506dcd6161a26961958efa4aa42e1"
		creation_date = "2024-10-25"
		last_modified = "2024-11-26"
		threat_name = "Windows.Trojan.Xeno"
		reference_sample = "b74733d68e95220ab0630a68ddf973b0c959fd421628e639c1b91e465ba9299b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Xeno with specific characteristics"
		filetype = "executable"

	strings:
		$sc_1 = { 8B 44 24 04 89 C6 FF 56 08 68 00 04 00 00 6A 08 50 FF 16 89 C3 8B 06 89 83 2C 01 00 00 8B 46 04 89 83 30 01 00 00 8B 46 08 89 83 34 01 00 00 8B 46 0C 89 83 38 }
		$sc_2 = { 55 48 89 E5 48 83 EC 40 49 89 CC 41 FF 54 24 10 48 89 C1 BA 08 00 00 00 41 B8 00 04 00 00 41 FF 14 24 48 89 C3 49 8B 04 24 48 89 83 90 01 00 00 49 8B 44 24 08 }
		$str_1 = "SharpInjector" ascii fullword
		$str_2 = "HEAVENSGATE_NON_OPERATIONAL" ascii fullword
		$str_3 = "ChromeDecryptor" ascii fullword
		$str_4 = "DataExtractionStructs" ascii fullword
		$str_5 = "XenoStealer" ascii fullword

	condition:
		(($sc_1 or $sc_2) and ($str_1 or $str_2)) and (1 of ($str_3,$str_4,$str_5))
}
