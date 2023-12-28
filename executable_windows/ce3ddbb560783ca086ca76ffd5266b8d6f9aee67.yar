rule BlackTech_Gh0stTimes_str
{
	meta:
		description = "Gh0stTimes in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash = "01581f0b1818db4f2cdd9542fd8d663896dc043efb6a80a92aadfac59ddb7684"
		os = "windows"
		filetype = "executable"

	strings:
		$msg1 = "new big loop connect %s %d ,sleep %d" ascii wide
		$msg2 = "small loop connect %s %d ,sleep %d" ascii wide
		$msg3 = "SockCon1=%d SockCon2=%d" ascii wide
		$msg4 = "connect  %s %d ok" ascii wide
		$msg5 = "connect failure %s %d" ascii wide
		$msg6 = "CFileManager" ascii wide
		$msg7 = "CKernelManager" ascii wide
		$msg8 = "CManager" ascii wide
		$msg9 = "CPortmapManager" ascii wide
		$msg10 = "CShellManager" ascii wide
		$msg11 = "CUltraPortmapManager" ascii wide
		$b1 = { C6 45 ?? DB C6 45 ?? 50 C6 45 ?? 62 }
		$b2 = { C6 45 ?? 7B C6 45 ?? 3A C6 45 ?? 79 C6 45 ?? 64 }
		$b3 = { C6 45 ?? 33 C6 45 ?? F4 C6 45 ?? 27 }
		$b4 = { C6 45 ?? 57 C6 45 ?? EA C6 45 ?? 9F C6 45 ?? 30 }
		$pdb = {73 76 63 68 6F 73 74 2D E5 85 A8 E5 8A 9F E8 83 BD 2D E5 8A A0 E5 AF 86 31 32 30 35 5C 52 65 6C 65 61 73 65 5C 73 76 63 68 6F 73 74 2E 70 64 62}

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and ( all of ($b*) or $pdb or 5 of ($msg*))
}
