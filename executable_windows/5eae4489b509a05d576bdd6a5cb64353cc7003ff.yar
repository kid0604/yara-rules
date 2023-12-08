import "pe"

rule HKTL_NET_GUID_SharpCookieMonster_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/m0rv4i/SharpCookieMonster"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "566c5556-1204-4db9-9dc8-a24091baaa8e" ascii wide
		$typelibguid0up = "566C5556-1204-4DB9-9DC8-A24091BAAA8E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
