import "pe"

rule HKTL_NET_GUID_Lime_Downloader_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Lime-Downloader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "ec7afd4c-fbc4-47c1-99aa-6ebb05094173" ascii wide
		$typelibguid0up = "EC7AFD4C-FBC4-47C1-99AA-6EBB05094173" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
