rule Linux_Cryptominer_Xmrig_271121fb
{
	meta:
		author = "Elastic Security"
		id = "271121fb-47cf-47a7-9e90-8565d4694c9e"
		fingerprint = "e0968731b0e006f3db92762822e4a3509d800e8f270b1c38303814fd672377a2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		reference_sample = "19aeafb63430b5ac98e93dfd6469c20b9c1145e6b5b86202553bd7bd9e118842"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrig"
		filetype = "executable"

	strings:
		$a = { 18 41 C1 E4 10 C1 E1 08 41 C1 EA 10 44 89 CB 41 C1 E9 18 C1 }

	condition:
		all of them
}
