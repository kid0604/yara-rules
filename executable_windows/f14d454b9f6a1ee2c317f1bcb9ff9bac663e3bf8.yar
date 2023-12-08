rule HKTL_NET_GUID_DotNetAVBypass_Master
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/lockfale/DotNetAVBypass-Master"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "4854c8dc-82b0-4162-86e0-a5bbcbc10240" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
