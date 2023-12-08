rule HKTL_NET_GUID_PoshSecFramework
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/PoshSec/PoshSecFramework"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "b1ac6aa0-2f1a-4696-bf4b-0e41cf2f4b6b" ascii nocase wide
		$typelibguid1 = "78bfcfc2-ef1c-4514-bce6-934b251666d2" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
