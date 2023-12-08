import "pe"

rule HKTL_NET_GUID_SharpSocks_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/SharpSocks"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "2f43992e-5703-4420-ad0b-17cb7d89c956" ascii wide
		$typelibguid0up = "2F43992E-5703-4420-AD0B-17CB7D89C956" ascii wide
		$typelibguid1lo = "86d10a34-c374-4de4-8e12-490e5e65ddff" ascii wide
		$typelibguid1up = "86D10A34-C374-4DE4-8E12-490E5E65DDFF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
