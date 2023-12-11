rule HKTL_NET_GUID_rundotnetdll32
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/rundotnetdll32"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a766db28-94b6-4ed1-aef9-5200bbdd8ca7" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
