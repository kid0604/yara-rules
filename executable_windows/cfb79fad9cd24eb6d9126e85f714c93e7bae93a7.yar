import "pe"

rule HKTL_NET_GUID_HTTPSBeaconShell_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "aca853dc-9e74-4175-8170-e85372d5f2a9" ascii wide
		$typelibguid0up = "ACA853DC-9E74-4175-8170-E85372D5F2A9" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
