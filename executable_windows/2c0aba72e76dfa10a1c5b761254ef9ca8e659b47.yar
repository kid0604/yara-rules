import "pe"

rule MALWARE_Win_DllHijacker01
{
	meta:
		author = "ditekSHen"
		description = "Hunt for VSNTAR21 / DllHijacker01 IronTiger / LuckyMouse / APT27 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "libvlc_add_intf" fullword ascii
		$s2 = "libvlc_dllonexit" fullword ascii
		$s3 = "libvlc_getmainargs" fullword ascii
		$s4 = "libvlc_initenv" fullword ascii
		$s5 = "libvlc_set_app_id" fullword ascii
		$s6 = "libvlc_set_app_type" fullword ascii
		$s7 = "libvlc_set_user_agent" fullword ascii
		$s8 = "libvlc_wait" fullword ascii
		$s9 = "dll.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}
