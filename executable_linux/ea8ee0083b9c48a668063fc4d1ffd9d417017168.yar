rule Linux_Trojan_Mirai_ad337d2f
{
	meta:
		author = "Elastic Security"
		id = "ad337d2f-d4ac-42a7-9d2e-576fe633fa16"
		fingerprint = "67cbcb8288fe319c3b8f961210748f7cea49c2f64fc2f1f55614d7ed97a86238"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference = "012b717909a8b251ec1e0c284b3c795865a32a1f4b79706d2254a4eb289c30a7"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 01 75 14 80 78 FF 2F 48 8D 40 FF 0F 94 C2 48 39 D8 77 EB 84 D2 }

	condition:
		all of them
}
