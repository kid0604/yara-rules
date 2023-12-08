import "pe"

rule HKTL_NET_GUID_ReverseShell_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/chango77747/ReverseShell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "980109e4-c988-47f9-b2b3-88d63fababdc" ascii wide
		$typelibguid0up = "980109E4-C988-47F9-B2B3-88D63FABABDC" ascii wide
		$typelibguid1lo = "8abe8da1-457e-4933-a40d-0958c8925985" ascii wide
		$typelibguid1up = "8ABE8DA1-457E-4933-A40D-0958C8925985" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
