rule HKTL_NET_GUID_DotNetToJScript
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/DotNetToJScript"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "7e3f231c-0d0b-4025-812c-0ef099404861" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
