rule Windows_Rootkit_R77_be403e3c
{
	meta:
		author = "Elastic Security"
		id = "be403e3c-a70d-4126-b464-83060138c79b"
		fingerprint = "46fd9d53771a0c6d14b364589a7cfa291a1c0405d74a97beac75db78faea7e0b"
		creation_date = "2023-05-18"
		last_modified = "2023-06-13"
		threat_name = "Windows.Rootkit.R77"
		reference_sample = "91c6e2621121a6871af091c52fafe41220ae12d6e47e52fd13a7b9edd8e31796"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Rootkit.R77"
		filetype = "executable"

	strings:
		$a = { 33 C9 48 89 8C 24 C0 00 00 00 4C 8B CB 48 89 8C 24 B8 00 00 00 45 33 C0 48 89 8C 24 B0 00 00 00 48 89 8C 24 A8 00 00 00 89 8C 24 A0 00 00 00 }

	condition:
		$a
}
