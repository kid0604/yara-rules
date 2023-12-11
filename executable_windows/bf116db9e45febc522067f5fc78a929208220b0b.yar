import "pe"

rule HKTL_NET_GUID_BYTAGE_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/KNIF/BYTAGE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "8e46ba56-e877-4dec-be1e-394cb1b5b9de" ascii wide
		$typelibguid0up = "8E46BA56-E877-4DEC-BE1E-394CB1B5B9DE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
