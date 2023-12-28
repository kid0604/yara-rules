rule Lazarus_BILDINGCAN_AES
{
	meta:
		description = "BILDINGCAN_AES in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "925922ef243fa2adbd138942a9ecb4616ab69580a1864429a1405c13702fe773 "
		os = "windows"
		filetype = "executable"

	strings:
		$AES = { 48 83 C3 04 30 43 FC 0F B6 44 1F FC 30 43 FD 0F B6 44 1F FD 30 43 FE 0F B6 44 1F FE 30 43 FF 48 FF C9 }
		$pass = "RC2zWLyG50fPIPkQ" wide
		$nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
		$confsize = { 48 8D ?? ?? ?? ?? 00 BA F0 06 00 00 E8 }
		$buffsize = { 00 00 C7 ?? ?? ??  B8 8E 03 00 }
		$rand = { 69 D2 ?? ?? 00 00 2B ?? 81 C? D2 04 00 00 }

	condition:
		uint16(0)==0x5a4d and 3 of them
}
