rule Linux_Exploit_Local_705c9589
{
	meta:
		author = "Elastic Security"
		id = "705c9589-f735-45ef-8cf0-b99a05905a9f"
		fingerprint = "d75edca622f0ab8a0b60c4ba5c1026c89d3613c0e101c5c12c03ee08cb7c576e"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "845727ea46491b46a665d4e1a3a9dbbe6cd0536d070f1c1efd533b91b75cdc88"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { 51 53 8D 0C 24 31 C0 B0 0B CD 80 31 C0 B0 01 CD }

	condition:
		all of them
}
