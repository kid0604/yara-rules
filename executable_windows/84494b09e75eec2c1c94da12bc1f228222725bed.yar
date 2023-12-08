import "pe"

rule HKTL_NET_GUID_Povlsomware_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/povlteksttv/Povlsomware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "fe0d5aa7-538f-42f6-9ece-b141560f7781" ascii wide
		$typelibguid0up = "FE0D5AA7-538F-42F6-9ECE-B141560F7781" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
