rule Linux_Generic_Threat_887671e9
{
	meta:
		author = "Elastic Security"
		id = "887671e9-1e93-42d9-afb8-a96d1a87c572"
		fingerprint = "55cbfbd761e2000492059909199d16faf6839d3d893e29987b73087942c9de78"
		creation_date = "2024-02-01"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "701c7c75ed6a7aaf59f5a1f04192a1f7d49d73c1bd36453aed703ad5560606dc"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 89 E5 57 56 53 83 E4 F0 83 EC 40 8B 45 0C E8 DC 04 00 00 81 C3 AC F7 0B 00 89 44 24 04 8B 45 08 89 04 24 E8 A7 67 00 00 85 C0 0F 88 40 04 00 00 C7 04 24 00 00 00 00 E8 03 F5 FF FF 8B 93 34 }

	condition:
		all of them
}
