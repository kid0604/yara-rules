rule HKTL_NET_GUID_SharpCradle
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/anthemtotheego/SharpCradle"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "f70d2b71-4aae-4b24-9dae-55bc819c78bb" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
