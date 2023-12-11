import "pe"

rule HKTL_NET_GUID_EWSToolkit_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/EWSToolkit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "ca536d67-53c9-43b5-8bc8-9a05fdc567ed" ascii wide
		$typelibguid0up = "CA536D67-53C9-43B5-8BC8-9A05FDC567ED" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
