import "pe"

rule HKTL_NET_GUID_OSSFileTool_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/B1eed/OSSFileTool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "207aca5d-dcd6-41fb-8465-58b39efcde8b" ascii wide
		$typelibguid0up = "207ACA5D-DCD6-41FB-8465-58B39EFCDE8B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
