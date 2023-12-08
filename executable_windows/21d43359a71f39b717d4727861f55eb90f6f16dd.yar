rule HKTL_NET_GUID_PlasmaRAT
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/mwsrc/PlasmaRAT"
		author = "Arnim Rupp"
		date = "2020-12-30"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "b8a2147c-074c-46e1-bb99-c8431a6546ce" ascii nocase wide
		$typelibguid1 = "0fcfde33-213f-4fb6-ac15-efb20393d4f3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
