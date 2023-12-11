import "pe"

rule APT_GreyEnergy_Malware_Oct18_1
{
	meta:
		description = "Detects samples from Grey Energy report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
		date = "2018-10-17"
		hash1 = "6c52a5850a57bea43a0a52ff0e2d2179653b97ae5406e884aee63e1cf340f58b"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%SystemRoot%\\System32\\thinmon.dll" fullword ascii
		$s2 = "'Cannot delete list entry (fatal error)!9The module %s cannot be executed on this system (0x%.4x).%Enumerate all sessions on TSE" wide
		$s8 = "cbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbecbe" ascii
		$s14 = "configure the service" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <700KB and pe.imphash()=="98d1ad672d0db4b4abdcda73cc9835cb" and all of them
}
