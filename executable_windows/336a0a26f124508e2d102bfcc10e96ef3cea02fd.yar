import "pe"

rule HKTL_NET_GUID_DInvoke_PoC_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/dtrizna/DInvoke_PoC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "5a869ab2-291a-49e6-a1b7-0d0f051bef0e" ascii wide
		$typelibguid0up = "5A869AB2-291A-49E6-A1B7-0D0F051BEF0E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
