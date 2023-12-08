rule Linux_Cryptominer_Xmrminer_2b250178
{
	meta:
		author = "Elastic Security"
		id = "2b250178-3f9a-4aeb-819a-970b5ef9c98a"
		fingerprint = "e297a790a78d32b973d6a028a09c96186c3971279b5c5eea4ff6409f12308e67"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		reference_sample = "636605cf63d3e335fe9481d4d110c43572e9ab365edfa2b6d16d96b52d6283ef"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { 03 7E 11 8B 44 24 38 89 EF 31 D2 89 06 8B 44 24 3C 89 46 04 F7 C7 02 00 }

	condition:
		all of them
}
