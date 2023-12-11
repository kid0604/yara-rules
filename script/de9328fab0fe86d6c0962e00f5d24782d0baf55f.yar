import "pe"

rule APT_Loader_MSIL_PGF_1
{
	meta:
		date_created = "2020-11-24"
		date_modified = "2020-11-24"
		description = "base.cs"
		md5 = "a495c6d11ff3f525915345fb762f8047"
		rev = 1
		author = "FireEye"
		os = "windows"
		filetype = "script"

	strings:
		$sb1 = { 72 [4] 6F [2] 00 0A 26 [0-16] 0? 6F [2] 00 0A [1-3] 0? 28 [2] 00 0A [0-1] 0? 72 [4-5] 0? 28 [2] 00 0A [0-1] 0? 6F [2] 00 0A 13 ?? 1? 13 ?? 38 [8-16] 91 [3-6] 8E 6? 5D 91 61 D2 9C 11 ?? 1? 58 13 [3-5] 8E 6? 3F }

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
