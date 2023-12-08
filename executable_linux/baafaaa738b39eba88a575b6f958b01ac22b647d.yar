rule Linux_Cryptominer_Xmrig_e7e64fb7
{
	meta:
		author = "Elastic Security"
		id = "e7e64fb7-e07c-4184-86bd-db491a2a11e0"
		fingerprint = "444240375f4b9c6948907c7e338764ac8221e5fcbbc2684bbd0a1102fef45e06"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Xmrig malware"
		filetype = "executable"

	strings:
		$a = { 03 48 89 74 24 48 77 05 48 8B 5C C4 30 4C 8B 0A 48 8B 0F 48 8B }

	condition:
		all of them
}
