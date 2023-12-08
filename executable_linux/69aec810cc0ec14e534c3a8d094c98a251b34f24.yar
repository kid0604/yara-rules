rule Linux_Cryptominer_Xmrminer_98b00f9c
{
	meta:
		author = "Elastic Security"
		id = "98b00f9c-354a-47dd-8546-a2842559d247"
		fingerprint = "8d231a490e818614141d6805a9e7328dc4b116b34fd027d5806043628b347141"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		reference_sample = "c01b88c5d3df7ce828e567bd8d639b135c48106e388cd81497fcbd5dcf30f332"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { 0F 38 DC DF 49 89 D4 66 0F 7F 24 1A 66 0F EF C3 66 42 0F 7F }

	condition:
		all of them
}
