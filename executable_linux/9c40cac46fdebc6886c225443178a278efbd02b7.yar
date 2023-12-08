rule Linux_Cryptominer_Camelot_83550472
{
	meta:
		author = "Elastic Security"
		id = "83550472-4c97-4afc-b187-1a7ffc9acbbc"
		fingerprint = "63cf1cf09ad06364e1b1f15774400e0544dbb0f38051fc795b4fc58bd08262d1"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "d2d8421ffdcebb7fed00edcf306ec5e86fc30ad3e87d55e85b05bea5dc1f7d63"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot"
		filetype = "executable"

	strings:
		$a = { FA 48 8D 4A 01 48 D1 E9 48 01 CA 48 29 F8 48 01 C3 49 89 C4 48 }

	condition:
		all of them
}
