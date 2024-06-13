rule Windows_Generic_Threat_420e1cdc
{
	meta:
		author = "Elastic Security"
		id = "420e1cdc-2d47-437a-986d-ff22d2fac978"
		fingerprint = "33f35c5c73656fc5987c39fabefa1225fef1734f4217518a1b6e7a78669c90c5"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "b20254e03f7f1e79fec51d614ee0cfe0cb87432f3a53cf98cf8c047c13e2d774"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 56 8B 75 08 85 F6 74 5A ?? ?? ?? ?? ?? 83 F8 03 75 16 56 E8 ED 01 00 00 59 85 C0 56 74 36 50 E8 0C 02 00 00 59 59 EB 3A 83 F8 02 75 26 8D 45 08 50 8D 45 FC 50 56 E8 25 0F 00 00 }

	condition:
		all of them
}
