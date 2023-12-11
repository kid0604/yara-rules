rule Linux_Hacktool_Exploitscan_4327f817
{
	meta:
		author = "Elastic Security"
		id = "4327f817-cb11-480f-aba7-4d5170c77758"
		fingerprint = "3f70c8ef8f20f763dcada4353c254fe1df238829ce590fb87c279d8a892cf9c4"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Exploitscan"
		reference_sample = "66c6d0e58916d863a1a973b4f5cb7d691fbd01d26b408dbc8c74f0f1e4088dfb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Exploitscan"
		filetype = "executable"

	strings:
		$a = { 24 08 8B 4C 24 0C 85 C0 74 20 8B 58 20 84 03 83 C3 10 8B 68 24 89 9C 24 DC 00 }

	condition:
		all of them
}
