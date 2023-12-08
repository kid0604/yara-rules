rule HKTL_NET_GUID_SharpSecDump
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/G0ldenGunSec/SharpSecDump"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "e2fdd6cc-9886-456c-9021-ee2c47cf67b7" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
