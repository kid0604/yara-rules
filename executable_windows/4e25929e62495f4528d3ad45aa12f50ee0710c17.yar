rule Windows_Trojan_GhostPulse_3673d337
{
	meta:
		author = "Elastic Security"
		id = "3673d337-218b-4ea8-93f5-ecbc6fe51885"
		fingerprint = "0b46a0e04ab2ca2760b2ace397a09b681bc6c0da5581c3f0f5cdb1a60f307a15"
		creation_date = "2023-12-11"
		last_modified = "2024-01-12"
		threat_name = "Windows.Trojan.GhostPulse"
		reference_sample = "3013ba32838f6d97d7d75e25394f9611b1c5def94d93588f0a05c90b25b7d6d5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan GhostPulse (3673d337) in file or memory"
		filetype = "executable"

	strings:
		$IDAT_parser_x86 = { 80 F9 3F 75 ?? 38 54 1E 02 74 ?? 80 FA 3F 75 ?? 38 6C 1E 03 74 ?? 80 FD 3F 75 ?? 8A 74 24 04 38 74 1E 04 }
		$IDAT_parser_x64 = { 80 FB 3F 0F 94 44 24 27 3C 3F 0F 94 44 24 30 40 80 FF 3F 0F 94 44 24 31 41 80 FD 3F 0F 94 44 24 32 41 80 FC 3F 0F 94 44 24 33 }

	condition:
		any of them
}
