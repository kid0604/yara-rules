rule HKTL_NET_GUID_WheresMyImplant
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/WheresMyImplant"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "cca59e4e-ce4d-40fc-965f-34560330c7e6" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
