rule Linux_Trojan_Mirai_fe721dc5
{
	meta:
		author = "Elastic Security"
		id = "fe721dc5-c2bc-4fa6-bdbc-589c6e033e6b"
		fingerprint = "ab7f571a3a3f6b50b9e120612b3cc34d654fc824429a2971054ca0d078ecb983"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 89 18 EB E1 57 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 }

	condition:
		all of them
}
