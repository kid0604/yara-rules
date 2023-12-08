import "pe"

rule HackTool_MSIL_SharPivot_1
{
	meta:
		date_created = "2020-11-25"
		date_modified = "2020-11-25"
		md5 = "e4efa759d425e2f26fbc29943a30f5bd"
		rev = 3
		author = "FireEye"
		description = "Detects the presence of HackTool MSIL SharPivot 1"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = { 73 ?? 00 00 0A 0A 06 1F ?? 1F ?? 6F ?? 00 00 0A 0B 73 ?? 00 00 0A 0C 16 13 04 2B 5E 23 [8] 06 6F ?? 00 00 0A 5A 23 [8] 58 28 ?? 00 00 0A 28 ?? 00 00 0A 28 ?? 00 00 0A }
		$s3 = "cmd_rpc" wide
		$s4 = "costura"

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}
