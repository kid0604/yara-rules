rule HKTL_CobaltStrike_Beacon_4_2_Decrypt
{
	meta:
		author = "Elastic"
		description = "Identifies deobfuscation routine used in Cobalt Strike Beacon DLL version 4.2"
		reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
		date = "2021-03-16"
		os = "windows"
		filetype = "executable"

	strings:
		$a_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
		$a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}

	condition:
		any of them
}
