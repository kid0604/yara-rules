rule HKTL_NET_GUID_RunAsUser
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/atthacks/RunAsUser"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "9dff282c-93b9-4063-bf8a-b6798371d35a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
