import "pe"

rule HKTL_NET_GUID_SharpDir_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpDir"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c7a07532-12a3-4f6a-a342-161bb060b789" ascii wide
		$typelibguid0up = "C7A07532-12A3-4F6A-A342-161BB060B789" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
