rule HKTL_NET_GUID_BlackNET
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/BlackHacker511/BlackNET"
		author = "Arnim Rupp"
		date = "2020-12-30"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c2b90883-abee-4cfa-af66-dfd93ec617a5" ascii nocase wide
		$typelibguid1 = "8bb6f5b4-e7c7-4554-afd1-48f368774837" ascii nocase wide
		$typelibguid2 = "983ae28c-91c3-4072-8cdf-698b2ff7a967" ascii nocase wide
		$typelibguid3 = "9ac18cdc-3711-4719-9cfb-5b5f2d51fd5a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
