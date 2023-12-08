rule HKTL_NET_GUID_Stealer
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malwares/Stealer"
		author = "Arnim Rupp"
		date = "2020-12-29"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8fcd4931-91a2-4e18-849b-70de34ab75df" ascii nocase wide
		$typelibguid1 = "e48811ca-8af8-4e73-85dd-2045b9cca73a" ascii nocase wide
		$typelibguid2 = "d3d8a1cc-e123-4905-b3de-374749122fcf" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
