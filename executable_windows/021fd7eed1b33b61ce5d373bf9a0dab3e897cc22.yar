rule HKTL_NET_GUID_AddReferenceDotRedTeam
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ceramicskate0/AddReferenceDotRedTeam"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "73c79d7e-17d4-46c9-be5a-ecef65b924e4" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
