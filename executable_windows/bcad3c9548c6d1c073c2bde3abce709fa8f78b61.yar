import "pe"

rule APT_Trojan_Win_REDFLARE_8
{
	meta:
		date_created = "2020-12-02"
		date_modified = "2020-12-02"
		md5 = "9c8eb908b8c1cda46e844c24f65d9370, 9e85713d615bda23785faf660c1b872c"
		rev = 1
		author = "FireEye"
		description = "Yara rule for detecting APT Trojan Win REDFLARE 8"
		os = "windows"
		filetype = "executable"

	strings:
		$1 = "PSRunner.PSRunner" fullword
		$2 = "CorBindToRuntime" fullword
		$3 = "ReportEventW" fullword
		$4 = "InvokePS" fullword wide
		$5 = "runCommand" fullword
		$6 = "initialize" fullword
		$trap = { 03 40 00 80 E8 [4] CC }

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}
