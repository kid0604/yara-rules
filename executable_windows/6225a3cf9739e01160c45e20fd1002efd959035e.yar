rule Windows_Generic_Threat_b509dfc8
{
	meta:
		author = "Elastic Security"
		id = "b509dfc8-6ec3-4315-a1ec-61e6b65793e7"
		fingerprint = "bb1e607fe0d84f25c9bd09d31614310e204dce17c4050be6ce7dc6ed9dfd8f92"
		creation_date = "2024-01-29"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "9b5124e5e1be30d3f2ad1020bbdb93e2ceeada4c4d36f71b2abbd728bd5292b8"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 00 00 0A 6F 29 00 00 0A 6F 2A 00 00 0A 13 04 11 04 28 22 00 00 0A 28 2B 00 00 0A 2D 0D 11 04 28 22 00 00 0A 28 2C 00 00 0A 26 06 28 2D 00 00 0A 2C 0F 06 73 28 00 00 0A 13 05 11 05 6F 2E 00 }

	condition:
		all of them
}
