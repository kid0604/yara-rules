import "pe"

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_6
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "00a43d64f9b5187a1e1f922b99b09b77"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		os = "windows"
		filetype = "executable"

	strings:
		$ss1 = "C:\\Programdata\\" wide
		$ss2 = "devobj.dll" wide fullword
		$ss3 = "msvcr100.dll" wide fullword
		$ss4 = "TpmVscMgrSvr.exe" wide fullword
		$ss5 = "\\Microsoft\\Windows\\TPM" wide fullword
		$ss6 = "CreateFileW" ascii fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x010B) and all of them
}
