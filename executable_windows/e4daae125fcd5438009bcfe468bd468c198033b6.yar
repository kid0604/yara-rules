import "pe"

rule malware_DtSftDriverLoader
{
	meta:
		description = "Hunt DtSftDriverLoader"
		author = "JPCERT/CC Incident Response Group"
		os = "windows"
		filetype = "executable"

	strings:
		$func0 = { 0F BE 1C 16 33 D9 81 E3 FF 00 00 00 C1 E9 08 33 0C 9D ?? ?? ?? ?? 42 3B D0 }
		$func1 = { 4A 83 CA FC 42 8A 14 3A 30 14 08 40 3B C6 }

	condition:
		( uint16(0)==0x5A4D) and ( filesize >50KB) and ( filesize <600KB) and ( all of ($func*))
}
