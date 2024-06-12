rule Linux_Generic_Threat_aa0c23d5
{
	meta:
		author = "Elastic Security"
		id = "aa0c23d5-e633-4898-91f8-3cf84c9dd6af"
		fingerprint = "acd33e82bcefde691df1cf2739518018f05e0f03ef2da692f3ccca810c2ef361"
		creation_date = "2024-05-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "8314290b81b827e1a1d157c41916a41a1c033e4f74876acc6806ed79ebbcc13d"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic threats on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F }
		$a2 = { 77 66 6F 66 60 6C 6E 62 67 6E 6A 6D }
		$a3 = { 62 67 6E 6A 6D 77 66 6F 66 60 6C 6E }

	condition:
		all of them
}
