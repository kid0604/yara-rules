import "pe"

rule HKTL_NET_GUID_Marauder_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/maraudershell/Marauder"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "fff0a9a3-dfd4-402b-a251-6046d765ad78" ascii wide
		$typelibguid0up = "FFF0A9A3-DFD4-402B-A251-6046D765AD78" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
