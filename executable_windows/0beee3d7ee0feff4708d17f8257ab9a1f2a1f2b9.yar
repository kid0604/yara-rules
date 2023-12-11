rule Equation_Kaspersky_TripleFantasy_Loader_alt_1
{
	meta:
		description = "Equation Group Malware - TripleFantasy Loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "4ce6e77a11b443cc7cbe439b71bf39a39d3d7fa3"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Original Innovations, LLC" fullword wide
		$x2 = "Moniter Resource Protocol" fullword wide
		$x3 = "ahlhcib.dll" fullword wide
		$s0 = "hnetcfg.HNetGetSharingServicesPage" fullword ascii
		$s1 = "hnetcfg.IcfGetOperationalMode" fullword ascii
		$s2 = "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
		$s3 = "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
		$s4 = "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
		$s5 = "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50000 and ( all of ($x*) and all of ($s*))
}
