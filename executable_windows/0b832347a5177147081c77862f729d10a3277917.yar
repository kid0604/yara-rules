import "pe"

rule HKTL_NET_GUID_NoAmci_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/med0x2e/NoAmci"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "352e80ec-72a5-4aa6-aabe-4f9a20393e8e" ascii wide
		$typelibguid0up = "352E80EC-72A5-4AA6-AABE-4F9A20393E8E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
