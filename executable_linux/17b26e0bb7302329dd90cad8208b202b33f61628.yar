rule Linux_Trojan_Mirai_389ee3e9
{
	meta:
		author = "Elastic Security"
		id = "389ee3e9-70c1-4c93-a999-292cf6ff1652"
		fingerprint = "59f2359dc1f41d385d639d157b4cd9fc73d76d8abb7cc09d47632bb4c9a39e6e"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 389ee3e9"
		filetype = "executable"

	strings:
		$a = { 89 45 00 EB 2C 8B 4B 04 8B 13 8B 7B 18 8B 01 01 02 8B 02 83 }

	condition:
		all of them
}
