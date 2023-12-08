import "pe"

rule HKTL_NET_GUID_TruffleSnout_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/dsnezhkov/TruffleSnout"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "33842d77-bce3-4ee8-9ee2-9769898bb429" ascii wide
		$typelibguid0up = "33842D77-BCE3-4EE8-9EE2-9769898BB429" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
