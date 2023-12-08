import "pe"

rule HKTL_NET_GUID_SharpExec_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/anthemtotheego/SharpExec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "7fbad126-e21c-4c4e-a9f0-613fcf585a71" ascii wide
		$typelibguid0up = "7FBAD126-E21C-4C4E-A9F0-613FCF585A71" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
