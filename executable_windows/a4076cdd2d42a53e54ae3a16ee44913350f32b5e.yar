rule HKTL_NET_GUID_Net_GPPPassword
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/outflanknl/Net-GPPPassword"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "00fcf72c-d148-4dd0-9ca4-0181c4bd55c3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
