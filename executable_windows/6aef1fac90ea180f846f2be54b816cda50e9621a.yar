rule HKTL_NET_GUID_LethalHTA
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/codewhitesec/LethalHTA"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "784cde17-ff0f-4e43-911a-19119e89c43f" ascii nocase wide
		$typelibguid1 = "7e2de2c0-61dc-43ab-a0ec-c27ee2172ea6" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
