rule Windows_Generic_Threat_bb480769
{
	meta:
		author = "Elastic Security"
		id = "bb480769-57fb-4c93-8330-450f563fd4c6"
		fingerprint = "9c58c2e028f99737574d49e47feb829058f6082414b58d6c9e569a50904591e7"
		creation_date = "2024-01-21"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "010e3aeb26533d418bb7d2fdcfb5ec21b36603b6abb63511be25a37f99635bce"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 89 E5 C6 45 03 B8 C7 45 08 BA EF BE AD C7 45 0C DE 89 10 BA C7 45 10 EF BE AD DE C7 45 14 89 50 04 B8 C7 45 18 EF BE AD DE C7 45 1C 6A 00 6A 01 C7 45 20 6A 00 FF D0 C7 45 24 B8 EF BE AD C7 }

	condition:
		all of them
}
