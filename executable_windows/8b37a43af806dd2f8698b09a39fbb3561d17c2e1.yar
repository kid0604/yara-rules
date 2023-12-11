import "pe"

rule HKTL_NET_GUID_SharpGPOAbuse_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FSecureLABS/SharpGPOAbuse"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "4f495784-b443-4838-9fa6-9149293af785" ascii wide
		$typelibguid0up = "4F495784-B443-4838-9FA6-9149293AF785" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
