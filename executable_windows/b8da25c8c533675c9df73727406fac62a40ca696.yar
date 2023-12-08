import "pe"

rule HKTL_NET_GUID_Net_GPPPassword_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/outflanknl/Net-GPPPassword"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "00fcf72c-d148-4dd0-9ca4-0181c4bd55c3" ascii wide
		$typelibguid0up = "00FCF72C-D148-4DD0-9CA4-0181C4BD55C3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
