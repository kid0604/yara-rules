import "pe"

rule APT_NK_MAL_M_Hunting_VEILEDSIGNAL_5
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		score = 75
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "6727284586ecf528240be21bb6e97f88"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		os = "windows"
		filetype = "executable"

	strings:
		$sb1 = { 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D [3] 48 8B CB FF 15 [4] EB }
		$ss1 = "chrome.exe" wide fullword
		$ss2 = "firefox.exe" wide fullword
		$ss3 = "msedge.exe" wide fullword
		$ss4 = "\\\\.\\pipe\\*" ascii fullword
		$ss5 = "FindFirstFileA" ascii fullword
		$ss6 = "Process32FirstW" ascii fullword
		$ss7 = "RtlAdjustPrivilege" ascii fullword
		$ss8 = "GetCurrentProcess" ascii fullword
		$ss9 = "NtWaitForSingleObject" ascii fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}
