rule Windows_Generic_Threat_808f680e
{
	meta:
		author = "Elastic Security"
		id = "808f680e-db35-488f-b942-79213890b336"
		fingerprint = "4b4b3b244d0168b11a8df4805f9043c6e4039ced332a7ba9c9d0d962ad6f6a0e"
		creation_date = "2024-01-10"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "df6955522532e365239b94e9d834ff5eeeb354eec3e3672c48be88725849ac1c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat based on specific fingerprint"
		filetype = "executable"

	strings:
		$a1 = { 28 00 00 0A 20 00 00 00 00 FE 01 2A 13 30 02 00 6C 00 00 00 01 00 00 11 20 00 00 00 00 FE 0E 00 00 38 54 00 00 00 00 FE 0C 00 00 20 01 00 00 00 FE 01 39 12 00 00 00 FE 09 01 00 FE 09 02 00 51 }

	condition:
		all of them
}
