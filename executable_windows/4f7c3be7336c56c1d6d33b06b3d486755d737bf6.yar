rule HKTL_NET_GUID_SharPersist
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fireeye/SharPersist"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "9d1b853e-58f1-4ba5-aefc-5c221ca30e48" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
