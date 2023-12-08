import "pe"

rule HKTL_NET_GUID_XORedReflectiveDLL_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/r3nhat/XORedReflectiveDLL"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c0e49392-04e3-4abb-b931-5202e0eb4c73" ascii wide
		$typelibguid0up = "C0E49392-04E3-4ABB-B931-5202E0EB4C73" ascii wide
		$typelibguid1lo = "30eef7d6-cee8-490b-829f-082041bc3141" ascii wide
		$typelibguid1up = "30EEF7D6-CEE8-490B-829F-082041BC3141" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
