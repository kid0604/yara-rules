import "pe"

rule HKTL_NET_GUID_SharpExcel4_DCOM_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/SharpExcel4-DCOM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "68b83ce5-bbd9-4ee3-b1cc-5e9223fab52b" ascii wide
		$typelibguid0up = "68B83CE5-BBD9-4EE3-B1CC-5E9223FAB52B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
