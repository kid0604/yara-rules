rule Linux_Trojan_Ddostf_cb0358a0
{
	meta:
		author = "Elastic Security"
		id = "cb0358a0-5303-4860-89ac-7dae037f5f0b"
		fingerprint = "f97c96d457532f2af5fb0e1b40ad13dcfba2479c651266b4bdd1ab2a01c0360f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ddostf"
		reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Ddostf malware"
		filetype = "executable"

	strings:
		$a = { 66 C7 45 F2 00 00 8D 45 F2 8B 55 E4 0F B6 12 88 10 0F B7 45 F2 0F }

	condition:
		all of them
}
