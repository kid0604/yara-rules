rule HKTL_NET_GUID_MemeVM
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TobitoFatitoRE/MemeVM"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "ef18f7f2-1f03-481c-98f9-4a18a2f12c11" ascii nocase wide
		$typelibguid1 = "77b2c83b-ca34-4738-9384-c52f0121647c" ascii nocase wide
		$typelibguid2 = "14d5d12e-9a32-4516-904e-df3393626317" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
