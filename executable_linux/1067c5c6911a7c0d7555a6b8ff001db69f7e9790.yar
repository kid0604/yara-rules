rule Linux_Cryptominer_Ccminer_3c593bc3
{
	meta:
		author = "Elastic Security"
		id = "3c593bc3-cb67-41da-bef1-aad9e73c34f7"
		fingerprint = "0a382ef73d3b5d1b1ad223c66fc367cc5b6f2b23a9758002045076234f257dfe"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Ccminer"
		reference_sample = "dbb403a00c75ef2a74b41b8b58d08a6749f37f922de6cc19127a8f244d901c60"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Ccminer malware"
		filetype = "executable"

	strings:
		$a = { 20 83 5C DE C2 00 00 00 68 03 5C EB EA 00 00 00 48 03 1C DC }

	condition:
		all of them
}
