rule HKTL_NET_GUID_EvilFOCA
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ElevenPaths/EvilFOCA"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "f26bdb4a-5846-4bec-8f52-3c39d32df495" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
