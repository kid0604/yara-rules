rule HKTL_NET_GUID_AggressorScripts
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/harleyQu1nn/AggressorScripts"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "afd1ff09-2632-4087-a30c-43591f32e4e8" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
