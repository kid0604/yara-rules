rule Windows_Generic_Threat_c3c4e847
{
	meta:
		author = "Elastic Security"
		id = "c3c4e847-ef6f-430d-9778-d48326fb4eb0"
		fingerprint = "017a8ec014fed493018cff128b973bb648dbb9a0d1bede313d237651d3f6531a"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "86b37f0b2d9d7a810b5739776b4104f1ded3a1228c4ec2d104d26d8eb26aa7ba"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2E 3F 41 56 3F 24 5F 52 65 66 5F 63 6F 75 6E 74 40 55 41 70 69 44 61 74 61 40 40 40 73 74 64 40 40 }

	condition:
		all of them
}
