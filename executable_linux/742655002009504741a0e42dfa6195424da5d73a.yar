rule Linux_Cryptominer_Xmrig_7e42bf80
{
	meta:
		author = "Elastic Security"
		id = "7e42bf80-60a4-4d45-bf07-b96a188c6e6b"
		fingerprint = "cf3b74ae6ff38b0131763fbcf65fa21fb6fd4462d2571b298c77a43184ac5415"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		reference_sample = "551b6e6617fa3f438ec1b3bd558b3cbc981141904cab261c0ac082a697e5b07d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Xmrig"
		filetype = "executable"

	strings:
		$a = { 0F 70 F8 FF 66 0F 73 FD 04 66 44 0F EF ED 66 41 0F 73 FE 04 66 41 0F }

	condition:
		all of them
}
