import "pe"

rule HKTL_NET_GUID_SharpChromium
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/SharpChromium"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "2133c634-4139-466e-8983-9a23ec99e01b" ascii wide
		$typelibguid0up = "2133C634-4139-466E-8983-9A23EC99E01B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
