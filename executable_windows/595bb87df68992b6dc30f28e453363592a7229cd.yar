rule HKTL_NET_GUID_RunShellcode
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/zerosum0x0/RunShellcode"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a3ec18a3-674c-4131-a7f5-acbed034b819" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
