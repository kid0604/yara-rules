import "pe"

rule DLLBeacons
{
	meta:
		description = "for files:  kaslose64.dll, spoolsv.exe, kaslose.dll, croperdate64.dll"
		author = "TheDFIRReport"
		date = "2021-09-14"
		hash1 = "a4d92718e0a2e145d014737248044a7e11fb4fd45b683fcf7aabffeefa280413"
		hash2 = "0d575c22dfd30ca58f86e4cf3346180f2a841d2105a3dacfe298f9c7a22049a0"
		hash3 = "320296ea54f7e957f4fc8d78ec0c1658d1c04a22110f9ddffa6e5cb633a1679c"
		hash4 = "1b981b4f1801c31551d20a0a5aee7548ec169d7af5dbcee549aa803aeea461a0"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "f14m80.dll" fullword ascii
		$s2 = "\\dxdiag.exe" fullword ascii
		$s3 = "\\regedit.exe" fullword ascii
		$s4 = "\\notepad.exe" fullword ascii
		$s5 = "\\mmc.exe" fullword ascii
		$s6 = "spawn::resuming thread %02d" fullword ascii
		$s7 = "xYYyQDllwAZFpV51" fullword ascii
		$s8 = "thread [%d]: finished" fullword ascii
		$s9 = "wmi: error initialize COM security" fullword ascii
		$s10 = "error initializing COM" fullword ascii
		$s11 = "spawn::first wait failed: 0x%04x" fullword ascii
		$s12 = "wmi: connect to root\\cimv2 failed: 0x%08x" fullword ascii
		$s13 = "jmPekFtanAOGET_5" fullword ascii
		$s14 = "spawn::decrypted" fullword ascii
		$s15 = "eQ_Jt_fIrCE85LW3" fullword ascii
		$s16 = "dBfdWB3uu8sReye1" fullword ascii
		$s17 = "qpp0WQSPyuCnCEm3" fullword ascii
		$s18 = "zn9gkPgoo_dOORd3" fullword ascii
		$s19 = "wmi: probaly running on sandbox" fullword ascii
		$s20 = "spawn::finished" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and (8 of them )) or ( all of them )
}
