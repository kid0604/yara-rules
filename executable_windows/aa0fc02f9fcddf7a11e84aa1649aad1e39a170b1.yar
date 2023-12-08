rule HKTL_NET_GUID_physmem2profit
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FSecureLABS/physmem2profit"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "814708c9-2320-42d2-a45f-31e42da06a94" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
