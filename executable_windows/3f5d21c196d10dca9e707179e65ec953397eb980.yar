rule HKTL_NET_GUID_CsharpAmsiBypass
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/WayneJLee/CsharpAmsiBypass"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "4ab3b95d-373c-4197-8ee3-fe0fa66ca122" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
