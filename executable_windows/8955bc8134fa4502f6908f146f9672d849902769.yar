rule Windows_Generic_Threat_48cbdc20
{
	meta:
		author = "Elastic Security"
		id = "48cbdc20-386a-491e-8407-f7c4c348f2e9"
		fingerprint = "98db38ebd05e99171489828491e6acfc7c4322283b325ed99429f366b0ee01a6"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "7a7704c64e64d3a1f76fc718d5b5a5e3d46beeeb62f0493f22e50865ddf66594"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 5E 69 69 69 4E 42 42 42 3E 2E 2E 2E 25 }
		$a2 = { 24 2E 2E 2E 2F 41 41 41 3A 51 51 51 47 5D 5D 5D 54 69 69 69 62 }

	condition:
		all of them
}
