rule Linux_Generic_Threat_2c8d824c
{
	meta:
		author = "Elastic Security"
		id = "2c8d824c-4791-46a6-ba4d-5dcc09fdc638"
		fingerprint = "8e54bf3f6b7b563d773a1f5de0b37b8bec455c44f8af57fde9a9b684bb6f5044"
		creation_date = "2024-01-18"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "9106bdd27e67d6eebfaec5b1482069285949de10afb28a538804ce64add88890"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 38 48 89 5C 24 50 48 89 7C 24 60 48 89 4C 24 58 48 8B 10 48 8B 40 08 48 8B 52 28 FF D2 48 89 44 24 28 48 89 5C 24 18 48 8B 4C 24 50 31 D2 90 EB 03 48 FF C2 48 39 D3 7E 6C 48 8B 34 D0 }

	condition:
		all of them
}
