rule HKTL_NET_GUID_Simple_Loader
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cribdragg3r/Simple-Loader"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "035ae711-c0e9-41da-a9a2-6523865e8694" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
