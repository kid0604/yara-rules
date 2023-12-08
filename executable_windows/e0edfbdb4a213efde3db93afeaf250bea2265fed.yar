rule HKTL_NET_GUID_SharpExec
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/anthemtotheego/SharpExec"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "7fbad126-e21c-4c4e-a9f0-613fcf585a71" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
