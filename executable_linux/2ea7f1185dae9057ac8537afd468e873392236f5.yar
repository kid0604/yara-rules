rule Linux_Cryptominer_Xmrig_9f6ac00f
{
	meta:
		author = "Elastic Security"
		id = "9f6ac00f-1562-4be1-8b54-bf9a89672b0e"
		fingerprint = "77b171a3099327a5edb59b8f1b17fb3f415ab7fd15beabcd3b53916cde206568"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		reference_sample = "9cd58c1759056c0c5bbd78248b9192c4f8c568ed89894aff3724fdb2be44ca43"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrig malware"
		filetype = "executable"

	strings:
		$a = { B8 31 75 00 00 83 E3 06 09 D9 01 C9 D3 F8 89 C1 }

	condition:
		all of them
}
