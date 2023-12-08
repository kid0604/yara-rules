import "pe"

rule HKTL_NET_GUID_CinaRAT_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/wearelegal/CinaRAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "8586f5b1-2ef4-4f35-bd45-c6206fdc0ebc" ascii wide
		$typelibguid0up = "8586F5B1-2EF4-4F35-BD45-C6206FDC0EBC" ascii wide
		$typelibguid1lo = "fe184ab5-f153-4179-9bf5-50523987cf1f" ascii wide
		$typelibguid1up = "FE184AB5-F153-4179-9BF5-50523987CF1F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
