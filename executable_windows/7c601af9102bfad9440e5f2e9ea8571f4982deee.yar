rule HKTL_NET_GUID_njRAT
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/mwsrc/njRAT"
		author = "Arnim Rupp"
		date = "2020-12-30"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "5a542c1b-2d36-4c31-b039-26a88d3967da" ascii nocase wide
		$typelibguid1 = "6b07082a-9256-42c3-999a-665e9de49f33" ascii nocase wide
		$typelibguid2 = "c0a9a70f-63e8-42ca-965d-73a1bc903e62" ascii nocase wide
		$typelibguid3 = "70bd11de-7da1-4a89-b459-8daacc930c20" ascii nocase wide
		$typelibguid4 = "fc790ee5-163a-40f9-a1e2-9863c290ff8b" ascii nocase wide
		$typelibguid5 = "cb3c28b2-2a4f-4114-941c-ce929fec94d3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
