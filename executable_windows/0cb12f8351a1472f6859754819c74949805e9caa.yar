rule Windows_Trojan_SolarMarker_08bfc26b
{
	meta:
		author = "Elastic Security"
		id = "08bfc26b-efda-49b4-b685-57edca8b9d18"
		fingerprint = "9c0c4a5bce63c9d99d53813f7250b3ccc395cb99eaebb8c016f8c040fbfa4ea7"
		creation_date = "2024-05-29"
		last_modified = "2024-06-12"
		threat_name = "Windows.Trojan.SolarMarker"
		reference_sample = "c1a6d2d78cc50f080f1fe4cadc6043027bf201d194f2b73625ce3664433a3966"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan SolarMarker variant 08bfc26b"
		filetype = "executable"

	strings:
		$a1 = { 07 09 91 61 D2 9C 09 20 C8 00 00 00 5D 16 FE 01 16 FE 01 13 }
		$a2 = { 91 07 08 91 61 D2 9C 08 20 C8 00 00 00 5D 16 FE 01 16 FE 01 }
		$a3 = { 06 08 06 08 91 07 08 91 61 D2 9C 08 20 C8 00 00 00 5D 16 FE }

	condition:
		any of them
}
