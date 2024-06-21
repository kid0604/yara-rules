rule malware_DOPLUGS
{
	meta:
		description = "DOPLUGS"
		author = "JPCERT/CC Incident Response Group"
		hash = "2a6015505c83113ff89d8a4be66301a3e6245a41"
		os = "windows"
		filetype = "executable"

	strings:
		$data1 = "CLSID" ascii wide
		$enc1 = {8B 14 24 8A 5C 14 10 8B 0C 24 88 DF F6 D7 20 CF F6 D1 20 D9 08 F9 88 4C 14 10 8B 0C 24 41 EB}
		$enc2 = {8B 14 24 89 D0 80 E2 ?? F6 D0 24 ?? 08 ??}

	condition:
		uint16(0)==0x5A4D and all of them
}
