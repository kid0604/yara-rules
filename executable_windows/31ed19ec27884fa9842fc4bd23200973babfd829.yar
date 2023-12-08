rule HKTL_NET_GUID_SharpKatz
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/b4rtik/SharpKatz"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8568b4c1-2940-4f6c-bf4e-4383ef268be9" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
