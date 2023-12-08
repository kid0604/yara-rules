rule HKTL_NET_GUID_CVE_2019_1064
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/RythmStick/CVE-2019-1064"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "ff97e98a-635e-4ea9-b2d0-1a13f6bdbc38" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
