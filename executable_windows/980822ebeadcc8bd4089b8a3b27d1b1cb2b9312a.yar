import "pe"

rule HKTL_NET_GUID_EvilWMIProvider_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/sunnyc7/EvilWMIProvider"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "a4020626-f1ec-4012-8b17-a2c8a0204a4b" ascii wide
		$typelibguid0up = "A4020626-F1EC-4012-8B17-A2C8A0204A4B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
