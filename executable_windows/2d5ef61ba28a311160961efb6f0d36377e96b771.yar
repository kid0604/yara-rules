import "pe"

rule HKTL_NET_GUID_MalSCCM
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/MalSCCM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "5439cecd-3bb3-4807-b33f-e4c299b71ca2" ascii wide
		$typelibguid0up = "5439CECD-3BB3-4807-B33F-E4C299B71CA2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
