import "pe"

rule HKTL_NET_GUID_sitrep_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/sitrep"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "12963497-988f-46c0-9212-28b4b2b1831b" ascii wide
		$typelibguid0up = "12963497-988F-46C0-9212-28B4B2B1831B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
