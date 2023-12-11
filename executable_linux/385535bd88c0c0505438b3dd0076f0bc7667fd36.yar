rule Linux_Cryptominer_Xmrminer_67bf4b54
{
	meta:
		author = "Elastic Security"
		id = "67bf4b54-aa02-4f4c-ba70-3f2db1418c7e"
		fingerprint = "5f2fae0eee79dac3c202796d987ad139520fadae145c84ab5769d46afb2518c2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		reference_sample = "9d33fba4fda6831d22afc72bf3d6d5349c5393abb3823dfa2a5c9e391d2b9ddf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { 46 70 4A 8B 2C E0 83 7D 00 03 74 DA 8B 4D 68 85 C9 74 DC 45 }

	condition:
		all of them
}
