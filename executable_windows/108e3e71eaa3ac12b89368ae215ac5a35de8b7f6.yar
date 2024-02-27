import "pe"

rule HKTL_NET_GUID_GMSAPasswordReader
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/rvazarkar/GMSAPasswordReader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-12-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c8112750-972d-4efa-a75b-da9b8a4533c7" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
