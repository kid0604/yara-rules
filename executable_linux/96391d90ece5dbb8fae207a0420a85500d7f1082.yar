rule Linux_Trojan_Ngioweb_994f1e97
{
	meta:
		author = "Elastic Security"
		id = "994f1e97-c370-4eb2-ac93-b5ebf112f55d"
		fingerprint = "6cc0ace6beb6c1bf4e10f9781bb551c10f48cc23efe9529d92b432b0ff88f245"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ngioweb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ngioweb"
		filetype = "executable"

	strings:
		$a = { C6 44 24 16 68 C6 44 24 15 63 C6 44 24 14 74 C6 44 24 13 61 C6 44 24 12 77 C6 44 24 11 2F C6 44 24 10 76 C6 44 24 0F 65 C6 44 24 0E 64 C6 44 24 0D 2F }

	condition:
		all of them
}
