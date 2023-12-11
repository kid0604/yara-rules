rule HKTL_NET_GUID_UAC_Escaper
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/UAC-Escaper"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "95359279-5cfa-46f6-b400-e80542a7336a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
