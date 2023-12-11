import "pe"

rule MALWARE_Osx_TechyUtils
{
	meta:
		author = "ditekSHen"
		description = "Detects TechyUtils OSX packages"
		clamav_sig = "MALWARE.Osx.Trojan.TechyUtils"
		os = "macos"
		filetype = "executable"

	strings:
		$s1 = "__ZL58__arclite_NSMutableDictionary__" ascii
		$s2 = "__ZL46__arclite_NSDictionary_" ascii
		$s3 = "<key>com.apple.security.get-task-allow</key>" fullword ascii
		$s4 = "/productprice.svc/GetCountryCode" ascii
		$s5 = "@_pthread_mutex_lock" fullword ascii
		$s6 = "_mh_execute_header" fullword ascii
		$s7 = "/Users/prasoon/Documents/" ascii
		$developerid = "Developer ID Application: Techyutils Software Private Limited (VS9Q8BRRRJ)" ascii

	condition:
		uint16(0)==0xfacf and ( all of ($s*) or $developerid)
}
