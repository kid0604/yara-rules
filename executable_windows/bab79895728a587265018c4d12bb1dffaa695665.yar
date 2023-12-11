import "pe"

rule HKTL_NET_GUID_TellMeYourSecrets_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/TellMeYourSecrets"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "9b448062-7219-4d82-9a0a-e784c4b3aa27" ascii wide
		$typelibguid0up = "9B448062-7219-4D82-9A0A-E784C4B3AA27" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
