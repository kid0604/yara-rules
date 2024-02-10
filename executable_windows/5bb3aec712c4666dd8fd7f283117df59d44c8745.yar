rule Windows_Generic_Threat_d6625ad7
{
	meta:
		author = "Elastic Security"
		id = "d6625ad7-7f2c-4445-a5f2-a9444425f3a4"
		fingerprint = "0e1bb99e22b53e6bb6350f95caaac592ddcad7695e72e298c7ab1d29d1dd4c1f"
		creation_date = "2024-01-29"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "878c9745320593573597d62c8f3adb3bef0b554cd51b18216f6d9f5d1a32a931"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2E 3F 41 56 3C 6C 61 6D 62 64 61 5F 31 3E 40 3F 4C 40 3F 3F 6F 6E 5F 65 76 65 6E 74 5F 61 64 64 40 43 6F 6D 70 6F 6E 65 6E 74 5F 4B 65 79 6C 6F 67 65 72 40 40 45 41 45 58 49 40 5A 40 }

	condition:
		all of them
}
