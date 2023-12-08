import "pe"

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_3
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		md5 = "c6441c961dcad0fe127514a918eaabd4"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		os = "windows"
		filetype = "executable"

	strings:
		$ss1 = { 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6A 73 6F 6E 2C 20 74 65 78 74 2F 6A 61 76 61 73 63 72 69 70 74 2C 20 2A 2F 2A 3B 20 71 3D 30 2E 30 31 00 00 61 63 63 65 70 74 00 00 65 6E 2D 55 53 2C 65 6E 3B 71 3D 30 2E 39 00 00 61 63 63 65 70 74 2D 6C 61 6E 67 75 61 67 65 00 63 6F 6F 6B 69 65 00 00 }
		$si1 = "HttpSendRequestW" fullword
		$si2 = "CreateNamedPipeW" fullword
		$si3 = "CreateThread" fullword
		$se1 = "DllGetClassObject" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}
