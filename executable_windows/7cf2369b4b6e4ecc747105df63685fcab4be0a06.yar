rule Windows_Generic_Threat_bd24be68
{
	meta:
		author = "Elastic Security"
		id = "bd24be68-3d72-44fd-92f2-39f592d47d0e"
		fingerprint = "35ff6c9b338ef95585d8d0059966857f6e5a426fa5f357acb844d264d239c70d"
		creation_date = "2024-01-12"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "fd159cf2f9bd48b0f6f5958eef8af8feede2bcbbea035a7e56ce1ff72d3f47eb"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 8B 4D 0C 56 8B 75 08 89 0E E8 AB 17 00 00 8B 48 24 89 4E 04 E8 A0 17 00 00 89 70 24 8B C6 5E 5D C3 55 8B EC 56 E8 8F 17 00 00 8B 75 08 3B 70 24 75 0E 8B 76 04 E8 7F 17 00 00 89 70 24 }

	condition:
		all of them
}
