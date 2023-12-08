rule HKTL_NET_GUID_DInvoke_PoC
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/dtrizna/DInvoke_PoC"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "5a869ab2-291a-49e6-a1b7-0d0f051bef0e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
