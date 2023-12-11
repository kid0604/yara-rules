import "pe"

rule HKTL_NET_GUID_ESC_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NetSPI/ESC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "06260ce5-61f4-4b81-ad83-7d01c3b37921" ascii wide
		$typelibguid0up = "06260CE5-61F4-4B81-AD83-7D01C3B37921" ascii wide
		$typelibguid1lo = "87fc7ede-4dae-4f00-ac77-9c40803e8248" ascii wide
		$typelibguid1up = "87FC7EDE-4DAE-4F00-AC77-9C40803E8248" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
