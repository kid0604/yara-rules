import "pe"

rule HKTL_NET_GUID_HWIDbypass_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/yunseok/HWIDbypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "47e08791-d124-4746-bc50-24bd1ee719a6" ascii wide
		$typelibguid0up = "47E08791-D124-4746-BC50-24BD1EE719A6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
