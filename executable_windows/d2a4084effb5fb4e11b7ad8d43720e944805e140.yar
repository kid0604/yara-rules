rule HKTL_NET_GUID_DInvisibleRegistry
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NVISO-BE/DInvisibleRegistry"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "31d576fb-9fb9-455e-ab02-c78981634c65" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
