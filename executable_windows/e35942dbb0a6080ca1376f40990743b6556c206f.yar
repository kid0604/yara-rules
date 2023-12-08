rule HKTL_NET_GUID_ysoserial_net
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/pwntester/ysoserial.net"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "e1e8c029-f7cd-4bd1-952e-e819b41520f0" ascii nocase wide
		$typelibguid1 = "6b40fde7-14ea-4f57-8b7b-cc2eb4a25e6c" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
