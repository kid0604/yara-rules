import "pe"

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_2
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "404b09def6054a281b41d309d809a428"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		os = "windows"
		filetype = "executable"

	strings:
		$sb1 = { C1 E0 05 4D 8? [2] 33 D0 45 69 C0 7D 50 BF 12 8B C2 41 FF C2 C1 E8 07 33 D0 8B C2 C1 E0 16 41 81 C0 87 D6 12 00 }
		$si1 = "CryptBinaryToStringA" fullword
		$si2 = "BCryptGenerateSymmetricKey" fullword
		$si3 = "CreateThread" fullword
		$ss1 = "ChainingModeGCM" wide
		$ss2 = "__tutma" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}
