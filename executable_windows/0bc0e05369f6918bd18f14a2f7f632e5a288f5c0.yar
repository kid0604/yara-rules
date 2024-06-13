rule Windows_Generic_Threat_b125fff2
{
	meta:
		author = "Elastic Security"
		id = "b125fff2-7b36-431f-8ed3-ccb6d4ff9483"
		fingerprint = "e2562c480b3ab0f0e6c5d396bc5d0584481348c1dd8edaac4484d9cb5d4a2b2e"
		creation_date = "2024-02-20"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "9c641c0c8c2fd8831ee4e3b29a2a65f070b54775e64821c50b8ccd387e602097"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 6F 00 00 0A 6F 70 00 00 0A 00 28 24 00 00 06 0A 06 2C 24 00 28 1B 00 00 06 0B 07 2C 19 00 28 CE 04 00 06 16 FE 01 0C 08 2C 0B 7E 03 00 00 04 6F D3 04 00 06 00 00 00 28 1A 00 00 06 00 28 18 00 }

	condition:
		all of them
}
