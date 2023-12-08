import "pe"

rule HKTL_NET_GUID_AllTheThings_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/johnjohnsp1/AllTheThings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "0547ff40-5255-42a2-beb7-2ff0dbf7d3ba" ascii wide
		$typelibguid0up = "0547FF40-5255-42A2-BEB7-2FF0DBF7D3BA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
