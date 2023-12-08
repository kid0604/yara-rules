import "pe"

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_4
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "404b09def6054a281b41d309d809a428"
		hash2 = "c6441c961dcad0fe127514a918eaabd4"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		os = "windows"
		filetype = "executable"

	strings:
		$sb1 = { FF 15 FC 76 01 00 8B F0 85 C0 74 ?? 8D 50 01 [6-16] FF 15 [4] 48 8B D8 48 85 C0 74 ?? 89 ?? 24 28 44 8B CD 4C 8B C? 48 89 44 24 20 }
		$sb2 = { 33 D2 33 C9 FF 15 [4] 4C 8B CB 4C 89 74 24 28 4C 8D 05 [2] FF FF 44 89 74 24 20 33 D2 33 C9 FF 15 }
		$si1 = "CreateThread" fullword
		$si2 = "MultiByteToWideChar" fullword
		$si3 = "LocalAlloc" fullword
		$se1 = "DllGetClassObject" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}
