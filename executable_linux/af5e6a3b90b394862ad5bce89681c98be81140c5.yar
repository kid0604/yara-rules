rule Linux_Trojan_Merlin_bbad69b8
{
	meta:
		author = "Elastic Security"
		id = "bbad69b8-e8fc-43ce-a620-793c059536fd"
		fingerprint = "594f385556978ef1029755cea53c3cf89ff4d6697be8769fe1977b14bbdb46d1"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Merlin"
		reference_sample = "d9955487f7d08f705e41a5ff848fb6f02d6c88286a52ec837b7b555fb422d1b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Merlin (bbad69b8) based on specific strings"
		filetype = "executable"

	strings:
		$a = { DA 31 C0 BB 1F 00 00 00 EB 12 0F B6 3C 13 40 88 3C 02 40 88 }

	condition:
		all of them
}
