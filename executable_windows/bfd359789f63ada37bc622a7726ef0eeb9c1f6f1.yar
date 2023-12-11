import "pe"

rule MALWARE_Win_Unknown_PackedLoader_01
{
	meta:
		author = "ditekShen"
		description = "Detects unknown loader / packer. Observed running LummaStealer"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Error at hooking API \"%S\"" wide
		$s2 = "Dumping first %d bytes:" wide
		$s3 = "Error at initialization of bundled DLL: %s" wide
		$s4 = "GetMemoryForDLL()" ascii
		$s5 = "type=activation&code=" ascii
		$s6 = "activation.php?code=" ascii
		$s7 = "&hwid=" ascii
		$s8 = "&hash=" ascii
		$s9 = "type=deactivation&hash=" ascii
		$s10 = "deactivation.php?hash=" ascii
		$s11 = "BANNED" fullword ascii
		$s12 = "GetAdaptersInfo" ascii

	condition:
		uint16(0)==0x5a4d and 11 of them
}
