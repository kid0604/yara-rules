rule HKTL_NET_GUID_AMSI_Handler
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/two06/AMSI_Handler"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "d829426c-986c-40a4-8ee2-58d14e090ef2" ascii nocase wide
		$typelibguid1 = "86652418-5605-43fd-98b5-859828b072be" ascii nocase wide
		$typelibguid2 = "1043649f-18e1-41c4-ae8d-ac4d9a86c2fc" ascii nocase wide
		$typelibguid3 = "1d920b03-c537-4659-9a8c-09fb1d615e98" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
