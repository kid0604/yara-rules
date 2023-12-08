rule HKTL_NET_GUID_WindowsRpcClients
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/WindowsRpcClients"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "843d8862-42eb-49ee-94e6-bca798dd33ea" ascii nocase wide
		$typelibguid1 = "632e4c3b-3013-46fc-bc6e-22828bf629e3" ascii nocase wide
		$typelibguid2 = "a2091d2f-6f7e-4118-a203-4cea4bea6bfa" ascii nocase wide
		$typelibguid3 = "950ef8ce-ec92-4e02-b122-0d41d83065b8" ascii nocase wide
		$typelibguid4 = "d51301bc-31aa-4475-8944-882ecf80e10d" ascii nocase wide
		$typelibguid5 = "823ff111-4de2-4637-af01-4bdc3ca4cf15" ascii nocase wide
		$typelibguid6 = "5d28f15e-3bb8-4088-abe0-b517b31d4595" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
