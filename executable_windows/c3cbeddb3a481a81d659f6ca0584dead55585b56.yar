import "pe"

rule APT_Tick_Sysmon_Loader_Jun18
{
	meta:
		description = "Detects Sysmon Loader from Tick group incident - Weaponized USB"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-tick-group-weaponized-secure-usb-drives-target-air-gapped-critical-systems/"
		date = "2018-06-23"
		hash1 = "31aea8630d5d2fcbb37a8e72fe4e096d0f2d8f05e03234645c69d7e8b59bb0e8"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "SysMonitor_3A2DCB47" fullword ascii
		$s1 = "msxml.exe" fullword ascii
		$s2 = "wins.log" fullword ascii
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\run" fullword ascii
		$s4 = "%2d-%2d-%2d-%2d" fullword ascii
		$s5 = "%USERPROFILE%" fullword ascii
		$s6 = "Windows NT" fullword ascii
		$s7 = "device monitor" fullword ascii
		$s8 = "\\Accessories" ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="c5bb16e79fb500c430edce9481ae5b2b" or $x1 or 6 of them )
}
