rule Linux_Trojan_Rekoobe_b41f70c2
{
	meta:
		author = "Elastic Security"
		id = "b41f70c2-abe4-425a-952f-5e0c9e572a76"
		fingerprint = "396fcb4333abe90f4c228d06c20eeff40f91e25fde312cc7760d999da0aa1027"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Rekoobe"
		reference_sample = "19c1a54279be1710724fc75a112741575936fe70379d166effc557420da714cd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Rekoobe"
		filetype = "executable"

	strings:
		$a = { E2 10 4D 31 D1 0F B6 D6 48 8B 14 D1 48 C1 E2 08 4C 31 CA 48 89 }

	condition:
		all of them
}
