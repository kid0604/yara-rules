rule HKTL_NET_GUID_SauronEye
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/vivami/SauronEye"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "0f43043d-8957-4ade-a0f4-25c1122e8118" ascii nocase wide
		$typelibguid1 = "086bf0ca-f1e4-4e8f-9040-a8c37a49fa26" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
