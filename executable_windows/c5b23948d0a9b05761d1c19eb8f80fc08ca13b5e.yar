rule Windows_Generic_Threat_05f52e4d
{
	meta:
		author = "Elastic Security"
		id = "05f52e4d-d131-491a-a037-069b450e3b3e"
		fingerprint = "f3d5f6dc1f9b51ce1700605c8a018000124d66a260771de0da1a321dc97872dd"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "e578b795f8ed77c1057d8e6b827f7426fd4881f02949bfc83bcad11fa7eb2403"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat based on specific file fingerprint"
		filetype = "executable"

	strings:
		$a1 = { 28 00 00 06 73 45 00 00 0A 73 46 00 00 0A 6F 47 00 00 0A 14 FE 06 29 00 00 06 73 45 00 00 0A 73 46 00 00 0A 0B 14 FE 06 2A 00 00 06 73 45 00 00 0A 73 46 00 00 0A 0C 07 6F 47 00 00 0A 08 6F 47 }

	condition:
		all of them
}
