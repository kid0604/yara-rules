rule HKTL_NET_GUID_SharpDomainSpray
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/HunnicCyber/SharpDomainSpray"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "76ffa92b-429b-4865-970d-4e7678ac34ea" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
