rule Linux_Cryptominer_Xmrig_bffa106b
{
	meta:
		author = "Elastic Security"
		id = "bffa106b-0a9a-4433-b9ac-ae41a020e7e0"
		fingerprint = "665b5684c55c88e55bcdb8761305d6428c6a8e810043bf9df0ba567faea4c435"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrig malware"
		filetype = "executable"

	strings:
		$a = { 54 24 9C 44 0F B6 94 24 BC 00 00 00 89 5C 24 A0 46 8B 0C 8A 66 0F 6E 5C }

	condition:
		all of them
}
