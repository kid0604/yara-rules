rule Linux_Trojan_Rekoobe_ab8ba790
{
	meta:
		author = "Elastic Security"
		id = "ab8ba790-d2dd-4756-af5c-6f78ba10c92d"
		fingerprint = "decdd02a583562380eda405dcb892d38558eb868743ebc44be592f4ae95b5971"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Rekoobe"
		reference_sample = "2aee0c74d9642ffab1f313179c26400acf60d7cbd2188bade28534d403f468d4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Rekoobe"
		filetype = "executable"

	strings:
		$a = { DB F9 66 0F 71 D1 08 66 0F 67 DD 66 0F DB E3 66 0F 71 D3 08 66 0F }

	condition:
		all of them
}
