import "pe"

rule MALWARE_Win_Apostle
{
	meta:
		author = "ditekSHen"
		description = "Detects Apsotle"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "bytesToBeEncrypted" fullword ascii
		$s2 = "SelfDelete" fullword ascii
		$s3 = "ReadMeFileName" ascii
		$s4 = "DesktopFileName" ascii
		$s5 = "SetWallpaper" fullword ascii
		$s6 = "get_EncryptionKey" fullword ascii
		$s7 = "disall" fullword ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}
