import "pe"

rule HKTL_NET_GUID_UrbanBishopLocal_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/slyd0g/UrbanBishopLocal"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "88b8515e-a0e8-4208-a9a0-34b01d7ba533" ascii wide
		$typelibguid0up = "88B8515E-A0E8-4208-A9A0-34B01D7BA533" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
