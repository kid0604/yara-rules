import "pe"

rule HKTL_NET_GUID_GRAT2_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/r3nhat/GRAT2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "5e7fce78-1977-444f-a18e-987d708a2cff" ascii wide
		$typelibguid0up = "5E7FCE78-1977-444F-A18E-987D708A2CFF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
