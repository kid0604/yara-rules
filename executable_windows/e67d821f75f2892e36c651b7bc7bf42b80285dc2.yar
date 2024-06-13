rule Windows_Generic_Threat_1636c2bf
{
	meta:
		author = "Elastic Security"
		id = "1636c2bf-5506-4651-9c4c-cd6454386301"
		fingerprint = "b0cd9f484d4191d42091300be33c72a29c073c297b4e46811555fc6d1ab0f482"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "6e43916db43d8217214bbe4eb32ed3d82d0ac423cffc91d053a317a3dbe6dafb"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 00 00 0A 28 22 00 00 0A 80 19 00 00 04 28 3B 00 00 06 28 2D 00 00 0A 28 45 00 00 06 16 80 1D 00 00 04 7E 13 00 00 04 7E 15 00 00 04 16 7E 15 00 00 04 8E B7 16 14 FE 06 43 00 00 06 73 63 00 }

	condition:
		all of them
}
