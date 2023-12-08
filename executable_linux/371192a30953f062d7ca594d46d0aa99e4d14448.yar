rule Linux_Backdoor_Generic_5776ae49
{
	meta:
		author = "Elastic Security"
		id = "5776ae49-64e9-46a0-a0bb-b0226eb9a8bd"
		fingerprint = "2d36fbe1820805c8fd41b2b34a2a2b950fc003ae4f177042dc0d2568925c5b76"
		creation_date = "2021-04-06"
		last_modified = "2022-01-26"
		threat_name = "Linux.Backdoor.Generic"
		reference_sample = "e247a5decb5184fd5dee0d209018e402c053f4a950dae23be59b71c082eb910c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux backdoor"
		filetype = "executable"

	strings:
		$a = { 18 C1 E8 08 88 47 12 8B 46 18 88 47 13 83 C4 1C 5B 5E 5F 5D }

	condition:
		all of them
}
