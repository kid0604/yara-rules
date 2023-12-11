rule HKTL_NET_GUID_DarkEye
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/K1ngSoul/DarkEye"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "0bdb9c65-14ed-4205-ab0c-ea2151866a7f" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
