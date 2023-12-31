import "pe"

rule MALWARE_Win_ISRStealer
{
	meta:
		author = "ditekSHen"
		description = "ISRStealer payload"
		clamav_sig = "MALWARE.Win.Trojan.ISRStealer"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "&password=" wide
		$s2 = "&pcname=" wide
		$s3 = "MSVBVM60.DLL" ascii
		$s4 = "MSVBVM60.DLL" wide
		$s5 = "Core Software For : Public" wide
		$s6 = "</Host>" wide
		$s7 = "</Pass>" wide
		$s8 = "/scomma" wide

	condition:
		( uint16(0)==0x5a4d and filesize <4000KB and 6 of them ) or all of them
}
