import "pe"

rule HKTL_NET_GUID_Tokenvator_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/Tokenvator"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "4b2b3bd4-d28f-44cc-96b3-4a2f64213109" ascii wide
		$typelibguid0up = "4B2B3BD4-D28F-44CC-96B3-4A2F64213109" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
