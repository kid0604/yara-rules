import "pe"

rule HKTL_NET_GUID_Stracciatella_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mgeeky/Stracciatella"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "eaafa0ac-e464-4fc4-9713-48aa9a6716fb" ascii wide
		$typelibguid0up = "EAAFA0AC-E464-4FC4-9713-48AA9A6716FB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
