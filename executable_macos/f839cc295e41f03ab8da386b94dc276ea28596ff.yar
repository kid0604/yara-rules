rule MacOS_Virus_Maxofferdeal_53df500f
{
	meta:
		author = "Elastic Security"
		id = "53df500f-3add-4d3d-aec3-35b7b5aa5b35"
		fingerprint = "2f41de7b8e55ef8db39bf84c0f01f8d34d67b087769b84381f2ccc3778e13b08"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Virus.Maxofferdeal"
		reference_sample = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Virus.Maxofferdeal"
		filetype = "executable"

	strings:
		$a = { BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }

	condition:
		all of them
}
