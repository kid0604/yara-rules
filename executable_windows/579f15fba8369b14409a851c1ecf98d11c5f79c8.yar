rule HKTL_NET_GUID_LockLess
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/LockLess"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a91421cb-7909-4383-ba43-c2992bbbac22" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
