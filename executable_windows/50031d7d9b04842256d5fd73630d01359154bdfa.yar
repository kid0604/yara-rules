rule HKTL_NET_GUID_iSpyKeylogger
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/mwsrc/iSpyKeylogger"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "ccc0a386-c4ce-42ef-aaea-b2af7eff4ad8" ascii nocase wide
		$typelibguid1 = "816b8b90-2975-46d3-aac9-3c45b26437fa" ascii nocase wide
		$typelibguid2 = "279b5533-d3ac-438f-ba89-3fe9de2da263" ascii nocase wide
		$typelibguid3 = "88d3dc02-2853-4bf0-b6dc-ad31f5135d26" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
