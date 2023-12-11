rule HKTL_NET_GUID_dotnet_gargoyle
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/countercept/dotnet-gargoyle"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "76435f79-f8af-4d74-8df5-d598a551b895" ascii nocase wide
		$typelibguid1 = "5a3fc840-5432-4925-b5bc-abc536429cb5" ascii nocase wide
		$typelibguid2 = "6f0bbb2a-e200-4d76-b8fa-f93c801ac220" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
