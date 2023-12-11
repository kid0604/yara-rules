rule HKTL_NET_GUID_Sharp_SMBExec
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/checkymander/Sharp-SMBExec"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "344ee55a-4e32-46f2-a003-69ad52b55945" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
