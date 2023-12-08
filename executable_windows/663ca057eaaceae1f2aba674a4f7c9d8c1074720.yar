rule HKTL_NET_GUID_SneakyExec
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/HackingThings/SneakyExec"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "612590aa-af68-41e6-8ce2-e831f7fe4ccc" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
