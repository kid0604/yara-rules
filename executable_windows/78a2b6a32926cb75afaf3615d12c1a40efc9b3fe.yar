rule HKTL_NET_GUID_IIS_backdoor
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/WBGlIl/IIS_backdoor"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "3fda4aa9-6fc1-473f-9048-7edc058c4f65" ascii nocase wide
		$typelibguid1 = "73ca4159-5d13-4a27-8965-d50c41ab203c" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
