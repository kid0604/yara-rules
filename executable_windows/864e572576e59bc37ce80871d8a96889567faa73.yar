rule HKTL_NET_GUID_SafetyKatz
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/SafetyKatz"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8347e81b-89fc-42a9-b22c-f59a6a572dec" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
