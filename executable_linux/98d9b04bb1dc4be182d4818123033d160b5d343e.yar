rule Linux_Trojan_Iroffer_711259e4
{
	meta:
		author = "Elastic Security"
		id = "711259e4-f081-4d81-8257-60ba733354c5"
		fingerprint = "aca63ef57ab6cb5579a2a5fea6095d88a3a4fb8347353febb3d02cc88a241b78"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Iroffer"
		reference_sample = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Iroffer"
		filetype = "executable"

	strings:
		$a = { 03 7E 2B 8B 45 C8 3D FF 00 00 00 77 21 8B 55 CC 81 FA FF 00 }

	condition:
		all of them
}
