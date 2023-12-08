rule Linux_Trojan_Xorddos_ca75589c
{
	meta:
		author = "Elastic Security"
		id = "ca75589c-6354-411b-b0a5-8400e657f956"
		fingerprint = "0bcaeae9ec0f5de241a05c77aadb5c3f2e39c84d03236971a0640ebae528a496"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "0448c1b2c7c738404ba11ff4b38cdc8f865ccf1e202f6711345da53ce46e7e16"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { 6D E0 25 01 00 00 00 55 8B EC C9 87 D1 87 0C 24 87 D1 8D 64 }

	condition:
		all of them
}
