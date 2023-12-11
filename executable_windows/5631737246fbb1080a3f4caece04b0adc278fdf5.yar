rule HKTL_NET_GUID_AtYourService
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mitchmoser/AtYourService"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "bc72386f-8b4c-44de-99b7-b06a8de3ce3f" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
