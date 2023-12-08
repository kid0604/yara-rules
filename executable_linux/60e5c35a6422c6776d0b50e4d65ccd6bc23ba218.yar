rule Linux_Exploit_Local_76c24b62
{
	meta:
		author = "Elastic Security"
		id = "76c24b62-e04f-410d-b7cb-668daa9aea20"
		fingerprint = "907cb776c9200b715c5b20475c2d4b16cb55c607dfb4b57bd3bd95368ce66257"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "330de2ca1add7e06389d94dfc541c367a484394c51663b26d27d89346b08ad1b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { 00 00 00 31 DB 89 D8 B0 17 CD 80 31 C0 50 50 B0 }

	condition:
		all of them
}
