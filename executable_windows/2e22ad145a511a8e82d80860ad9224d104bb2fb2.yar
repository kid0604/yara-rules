rule HKTL_NET_GUID_aresskit
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/BlackVikingPro/aresskit"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8dca0e42-f767-411d-9704-ae0ba4a44ae8" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
