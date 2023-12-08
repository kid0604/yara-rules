import "pe"

rule HKTL_NET_GUID_ShadowSpray
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/Dec0ne/ShadowSpray"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "7e47d586-ddc6-4382-848c-5cf0798084e1" ascii wide
		$typelibguid0up = "7E47D586-DDC6-4382-848C-5CF0798084E1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
