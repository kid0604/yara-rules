import "pe"

rule HKTL_NET_GUID_SharpLocker_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Pickfordmatt/SharpLocker"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "a6f8500f-68bc-4efc-962a-6c6e68d893af" ascii wide
		$typelibguid0up = "A6F8500F-68BC-4EFC-962A-6C6E68D893AF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
