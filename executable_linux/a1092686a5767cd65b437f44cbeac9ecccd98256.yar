rule Linux_Generic_Threat_936b24d5
{
	meta:
		author = "Elastic Security"
		id = "936b24d5-f8d7-44f1-a541-94c30a514a11"
		fingerprint = "087f31195b3eaf51cd03167a877e54a5ba3ca9941145d8125c823100ba6401c4"
		creation_date = "2024-01-18"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "fb8eb0c876148a4199cc873b84fd9c1c6abc1341e02d118f72ffb0dae37592a4"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic threat on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { 66 73 65 65 6B 6F 28 6F 70 74 2E 64 69 63 74 2C 20 30 4C 2C 20 53 45 45 4B 5F 45 4E 44 29 20 21 3D 20 2D 31 }

	condition:
		all of them
}
