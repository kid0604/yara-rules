rule Linux_Trojan_Mirai_485c4b13
{
	meta:
		author = "Elastic Security"
		id = "485c4b13-3c7c-47a7-b926-8237cb759ad7"
		fingerprint = "28f3e8982cee2836a59721c88ee0a9159ad6fdfc27c0091927f5286f3a731e9a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 485c4b13"
		filetype = "executable"

	strings:
		$a = { 7E 1F 8B 4C 24 4C 01 D1 0F B6 11 88 D0 2C 61 3C 19 77 05 80 }

	condition:
		all of them
}
