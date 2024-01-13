rule Windows_Generic_Threat_efdb9e81
{
	meta:
		author = "Elastic Security"
		id = "efdb9e81-9004-426e-b599-331560b7f0ff"
		fingerprint = "ce1499c8adaad552c127ae80dad90a39eb15e1e461afe3266e8cd6961d3fde79"
		creation_date = "2024-01-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "1c3302b14324c9f4e07829f41cd767ec654db18ff330933c6544c46bd19e89dd"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 4D 61 78 69 6D 75 6D 43 68 65 63 6B 42 6F 78 53 69 7A 65 }
		$a2 = { 56 69 73 75 61 6C 50 6C 75 73 2E 4E 61 74 69 76 65 }

	condition:
		all of them
}
