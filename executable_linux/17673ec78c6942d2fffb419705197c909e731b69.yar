rule Linux_Cryptominer_Generic_9c8f3b1a
{
	meta:
		author = "Elastic Security"
		id = "9c8f3b1a-0273-4164-ba48-b0bc090adf9e"
		fingerprint = "a35efe6bad4e0906032ab2fd7c776758e71caed8be402948f39682cf1f858005"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "74d8344139c5deea854d8f82970e06fc6a51a6bf845e763de603bde7b8aa80ac"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 6F 67 31 70 00 6C 6F 67 32 66 00 6C 6C 72 6F 75 6E 64 00 73 71 }

	condition:
		all of them
}
