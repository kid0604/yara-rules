rule HKTL_NET_GUID_bantam
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/gellin/bantam"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "14c79bda-2ce6-424d-bd49-4f8d68630b7b" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
