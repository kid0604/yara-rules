rule HKTL_NET_GUID_SharpAdidnsdump
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/b4rtik/SharpAdidnsdump"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "cdb02bc2-5f62-4c8a-af69-acc3ab82e741" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
