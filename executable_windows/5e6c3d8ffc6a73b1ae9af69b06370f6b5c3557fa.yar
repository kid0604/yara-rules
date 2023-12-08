import "pe"

rule PocketPCSHA
{
	meta:
		author = "malware-lu"
		description = "Detects PocketPCSHA malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 86 2F 96 2F A6 2F B6 2F 22 4F 43 68 53 6B 63 6A 73 69 F0 7F 0B D0 0B 40 09 00 09 D0 B3 65 A3 66 93 67 0B 40 83 64 03 64 04 D0 0B 40 09 00 10 7F 26 4F F6 6B F6 6A F6 69 0B 00 F6 68 [3] 00 [3] 00 [3] 00 22 4F F0 7F 0A D0 06 D4 06 D5 0B 40 09 }

	condition:
		$a0 at pe.entry_point
}
