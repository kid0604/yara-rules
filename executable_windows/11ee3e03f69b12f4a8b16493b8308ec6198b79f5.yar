import "pe"

rule HKTL_NET_GUID_BrowserPass_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jabiel/BrowserPass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "3cb59871-0dce-453b-857a-2d1e515b0b66" ascii wide
		$typelibguid0up = "3CB59871-0DCE-453B-857A-2D1E515B0B66" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
