rule HKTL_NET_GUID_PoshC2_Misc
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/PoshC2_Misc"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "85773eb7-b159-45fe-96cd-11bad51da6de" ascii nocase wide
		$typelibguid1 = "9d32ad59-4093-420d-b45c-5fff391e990d" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
