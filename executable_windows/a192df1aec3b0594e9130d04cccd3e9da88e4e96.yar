import "pe"

rule HKTL_NET_GUID_EasyNet_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/EasyNet"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "3097d856-25c2-42c9-8d59-2cdad8e8ea12" ascii wide
		$typelibguid0up = "3097D856-25C2-42C9-8D59-2CDAD8E8EA12" ascii wide
		$typelibguid1lo = "ba33f716-91e0-4cf7-b9bd-b4d558f9a173" ascii wide
		$typelibguid1up = "BA33F716-91E0-4CF7-B9BD-B4D558F9A173" ascii wide
		$typelibguid2lo = "37d6dd3f-5457-4d8b-a2e1-c7b156b176e5" ascii wide
		$typelibguid2up = "37D6DD3F-5457-4D8B-A2E1-C7B156B176E5" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
