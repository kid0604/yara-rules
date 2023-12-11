rule Generic_ATMPot : Generic_ATMPot
{
	meta:
		description = "Generic rule for Winpot aka ATMPot"
		author = "xylitol@temari.fr"
		date = "2019-02-24"
		reference = "https://securelist.com/atm-robber-winpot/89611/"
		os = "windows"
		filetype = "executable"

	strings:
		$api1 = "CSCCNG" ascii wide
		$api2 = "CscCngOpen" ascii wide
		$api3 = "CscCngClose" ascii wide
		$string1 = "%d,%02d;" ascii wide
		$hex1 = { FF 15 ?? ?? ?? ?? F6 C4 80 }
		$hex2 = { 25 31 5B ?? 2D ?? 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D }

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
