import "pe"

rule HKTL_NET_GUID_Minidump_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/3xpl01tc0d3r/Minidump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "15c241aa-e73c-4b38-9489-9a344ac268a3" ascii wide
		$typelibguid0up = "15C241AA-E73C-4B38-9489-9A344AC268A3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
