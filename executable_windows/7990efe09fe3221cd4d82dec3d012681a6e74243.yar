rule Windows_Trojan_Donutloader_21e801e0
{
	meta:
		author = "Elastic Security"
		id = "21e801e0-b016-48b2-81f5-930e7d3dd318"
		fingerprint = "8b971734d471f281e7c48177096359e8f43578a12e42f6203f55d5e79d9ed09d"
		creation_date = "2024-01-21"
		last_modified = "2024-02-08"
		threat_name = "Windows.Trojan.Donutloader"
		reference_sample = "c3bda62725bb1047d203575bbe033f0f95d4dd6402c05f9d0c69d24bd3224ca6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Donutloader"
		filetype = "executable"

	strings:
		$a = { 48 89 45 F0 48 8B 45 F0 48 81 C4 D0 00 00 00 5D C3 55 48 81 EC 60 02 00 00 48 8D AC 24 80 00 00 00 48 89 8D F0 01 00 00 48 89 95 F8 01 00 00 4C 89 85 00 02 00 00 4C 89 8D 08 02 00 00 48 C7 85 }

	condition:
		all of them
}
