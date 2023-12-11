rule Linux_Cryptominer_Stak_bb3153ac
{
	meta:
		author = "Elastic Security"
		id = "bb3153ac-b11b-4e84-afab-05dab61424ae"
		fingerprint = "c4c33125a1fad9ff393138b333a8cebfd67217e90780c45f73f660ed1fd02753"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Stak"
		reference_sample = "5b974b6e6a239bcdc067c53cc8a6180c900052d7874075244dc49aaaa9414cca"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Stak malware"
		filetype = "executable"

	strings:
		$a = { 6C 77 61 79 73 22 2C 20 22 6E 6F 5F 6D 6C 63 6B 22 2C 20 22 }

	condition:
		all of them
}
