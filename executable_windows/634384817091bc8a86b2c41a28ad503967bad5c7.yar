import "pe"

rule HKTL_NET_GUID_DarkFender_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xyg3n/DarkFender"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "12fdf7ce-4a7c-41b6-9b32-766ddd299beb" ascii wide
		$typelibguid0up = "12FDF7CE-4A7C-41B6-9B32-766DDD299BEB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
