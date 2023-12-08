rule Linux_Cryptominer_Camelot_8799d8d6
{
	meta:
		author = "Elastic Security"
		id = "8799d8d6-714b-4837-be60-884d78e3b8f3"
		fingerprint = "05c8d7c1d11352f2ec0b5d96a7b2378391ad9f8ae285a1299111aca38352f707"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "4a6d98eae8951e5b9e0a226f1197732d6d14ed45c1b1534d3cdb4413261eb352"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot"
		filetype = "executable"

	strings:
		$a = { 72 56 66 48 32 37 48 4D 5A 75 6D 74 46 75 4A 72 6D 48 47 38 }

	condition:
		all of them
}
