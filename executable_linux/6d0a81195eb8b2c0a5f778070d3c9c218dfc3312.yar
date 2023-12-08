rule Linux_Trojan_Iroffer_013e07de
{
	meta:
		author = "Elastic Security"
		id = "013e07de-95bd-4774-a14f-0a10f911a2dd"
		fingerprint = "92dde62076acec29a637b63a35f00c35f706df84d6ee9cabda0c6f63d01a13c4"
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
		$a = { 00 49 67 6E 6F 72 69 6E 67 20 42 61 64 20 58 44 43 43 20 4E 6F }

	condition:
		all of them
}
