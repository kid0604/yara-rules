rule Linux_Trojan_Mirai_0eba3f5a
{
	meta:
		author = "Elastic Security"
		id = "0eba3f5a-1aa8-4dc8-9f63-01bc4959792a"
		fingerprint = "c0f4f9a93672bce63c9e3cfc389c73922c1c24a2db7728ad7ebc1d69b4db150f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "2e4f89c76dfefd4b2bfd1cf0467ac0324026355723950d12d7ed51195fd998cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 0eba3f5a"
		filetype = "executable"

	strings:
		$a = { C3 55 48 89 E5 48 83 EC 40 48 89 7D C8 89 F0 66 89 45 C4 C7 45 DC 01 00 }

	condition:
		all of them
}
