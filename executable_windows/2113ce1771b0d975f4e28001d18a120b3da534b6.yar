import "pe"

rule HKTL_NET_GUID_DInvoke_alt_2
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TheWover/DInvoke"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "b77fdab5-207c-4cdb-b1aa-348505c54229" ascii wide
		$typelibguid0up = "B77FDAB5-207C-4CDB-B1AA-348505C54229" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
