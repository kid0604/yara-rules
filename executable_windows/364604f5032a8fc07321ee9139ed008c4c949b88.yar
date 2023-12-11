import "pe"

rule HKTL_NET_GUID_DotNetAVBypass_Master_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/lockfale/DotNetAVBypass-Master"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "4854c8dc-82b0-4162-86e0-a5bbcbc10240" ascii wide
		$typelibguid0up = "4854C8DC-82B0-4162-86E0-A5BBCBC10240" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
