rule HKTL_NET_GUID_USBTrojan
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mashed-potatoes/USBTrojan"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "4eee900e-adc5-46a7-8d7d-873fd6aea83e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
