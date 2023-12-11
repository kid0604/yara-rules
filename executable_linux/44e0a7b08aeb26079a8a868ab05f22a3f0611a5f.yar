rule Linux_Trojan_Mirai_6d96ae91
{
	meta:
		author = "Elastic Security"
		id = "6d96ae91-9d5c-48f1-928b-1562b120a74d"
		fingerprint = "fdbeaae0a96f3950d19aed497fae3e7a5517db141f53a1a6315b38b1d53d678b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "e3a1d92df6fb566e09c389cfb085126d2ea0f51a776ec099afb8913ef5e96f9b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint 6d96ae91"
		filetype = "executable"

	strings:
		$a = { 01 00 00 C1 00 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D }

	condition:
		all of them
}
