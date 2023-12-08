import "pe"

rule MALWARE_Osx_AMCPCVARK
{
	meta:
		author = "ditekSHen"
		description = "Detects OSX TechyUtils/PCVARK adware"
		clamav_sig = "MALWARE.Osx.Adware.AMC-PCVARK-TechyUtils"
		os = "macos"
		filetype = "executable"

	strings:
		$s1 = "Mac Auto Fixer.app" fullword ascii
		$s2 = "com.techyutil.macautofixer" fullword ascii
		$s3 = "com.findApp.findApp" ascii
		$s4 = "Library/Preferences/%@.plist" fullword ascii
		$s5 = "Library/%@/%@" fullword ascii
		$s6 = "Library/Application Support/%@/%@" fullword ascii
		$s7 = "sleep 3; rm -rf \"%@\"" fullword ascii
		$s8 = "Silently calling url: %@" ascii
		$cnc1 = "cloudfront.net/getdetails" ascii
		$cnc2 = "trk.entiretrack.com/trackerwcfsrv/tracker.svc/trackOffersAccepted/?" ascii
		$cnc3 = "pxl=%@&x-count=1&utm_source=%@&lpid=0&utm_content=&utm_term=&x-base=&utm_medium=%@&utm_publisher=%@&offerpxl=&x-fetch=1&utm_campaign=@&affiliateid=&x-at=&btnid=" ascii
		$x1 = "mafsysinfo" fullword ascii
		$x2 = "MAF4497_MAF4399_MAF2204" ascii
		$developerid = "Developer ID Application: Rahul Gahlot (RZ74UYT742)" ascii

	condition:
		uint16(0)==0xfacf and (6 of ($s*) or 2 of ($cnc*) or all of ($x*) or $developerid)
}
