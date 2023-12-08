import "pe"

rule HKTL_NET_GUID_k8fly_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/zzwlpx/k8fly"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-29"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "13b6c843-f3d4-4585-b4f3-e2672a47931e" ascii wide
		$typelibguid0up = "13B6C843-F3D4-4585-B4F3-E2672A47931E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
