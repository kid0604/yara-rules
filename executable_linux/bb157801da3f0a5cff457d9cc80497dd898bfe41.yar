rule Linux_Exploit_Vmsplice_055f88b8
{
	meta:
		author = "Elastic Security"
		id = "055f88b8-b1b0-4b02-8fc5-97804b564d27"
		fingerprint = "38f7d6c56ee1cd465062b5c82320710c4d0393a3b33f5586b6c0c0c778e5d3b2"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Vmsplice"
		reference_sample = "607c8c5edc8cbbd79a40ce4a0eccf46e01447985d9415d1eff6a91bf64074507"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Vmsplice"
		filetype = "executable"

	strings:
		$a = { 2D 2D 2D 00 20 4C 69 6E 75 78 20 76 6D 73 70 6C }

	condition:
		all of them
}
