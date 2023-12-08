rule Linux_Trojan_Tsunami_cbf50d9c
{
	meta:
		author = "Elastic Security"
		id = "cbf50d9c-2893-48c9-a2a9-45053f0a174b"
		fingerprint = "acb32177d07df40112d99ed0a2b7ed01fbca63df1f63387cf939caa4cf1cf83b"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "b64d0cf4fc4149aa4f63900e61b6739e154d328ea1eb31f4c231016679fc4aa5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami with fingerprint cbf50d9c"
		filetype = "executable"

	strings:
		$a = { 07 F8 BF 81 9C B8 20 07 09 20 35 15 11 03 20 85 }

	condition:
		all of them
}
