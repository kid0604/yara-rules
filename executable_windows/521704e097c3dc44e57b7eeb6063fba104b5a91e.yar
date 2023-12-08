rule HKTL_NET_GUID_Mass_RAT
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Mass-RAT"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "6c43a753-9565-48b2-a372-4210bb1e0d75" ascii nocase wide
		$typelibguid1 = "92ba2a7e-c198-4d43-929e-1cfe54b64d95" ascii nocase wide
		$typelibguid2 = "4cb9bbee-fb92-44fa-a427-b7245befc2f3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
