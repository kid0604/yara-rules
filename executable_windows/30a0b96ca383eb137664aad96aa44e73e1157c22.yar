rule Windows_Generic_Threat_b1ef4828
{
	meta:
		author = "Elastic Security"
		id = "b1ef4828-10bd-41f8-84b5-041bf3147c0b"
		fingerprint = "e867d9a0a489d95898f85578c71d7411eac3142539fcc88df51d1cf048d351a9"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "29b20ff8ebad05e4a33c925251d08824ca155f5d9fa72d6f9e359e6ec6c61279"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 70 36 72 20 74 24 76 28 78 2C 7A 30 7C 34 7E 38 7E 3C 7E 40 7E 54 7E 74 7E 7C 5D }
		$a2 = { 7E 30 7E 34 7E 43 7E 4F 7E 5A 7E 6E 7E 79 7E }

	condition:
		all of them
}
