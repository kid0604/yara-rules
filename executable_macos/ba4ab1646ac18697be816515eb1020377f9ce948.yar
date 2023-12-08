import "pe"

rule MALWARE_Osx_RealtimeSpy
{
	meta:
		author = "ditekSHen"
		description = "Detects macOS RealtimeSpy monitoring app"
		clamav_sig = "MALWARE.Osx.Trojan.RealtimeSpy"
		os = "macos"
		filetype = "executable"

	strings:
		$x1 = "SPYAGENT4HASHCIPHER" fullword ascii
		$x2 = ":username:password:acctid:compUser:compName:" ascii
		$x3 = ":username:password:acctid:compName:" ascii
		$x4 = "://www.realtime-spy-mac.com/" ascii
		$x5 = "/Users/spytech/" ascii
		$x6 = "shell script \"touch /private/var/db/.AccessibilityAPIEnabled\" password \"pwd\" with administrator privileges" ascii
		$x7 = "Content-Disposition: form-data; name=\"raptor_" ascii
		$c1 = "_OBJC_CLASS_$_LocationLogger" fullword ascii
		$c2 = "_OBJC_CLASS_$_MonitoringFunctions" fullword ascii
		$c3 = "_OBJC_CLASS_$_ProcessLogger" fullword ascii
		$c4 = "_OBJC_CLASS_$_RealtimeLoggingFunctions" fullword ascii
		$c5 = "_OBJC_CLASS_$_Realtime_SpyAppDelegate" fullword ascii
		$c6 = "_OBJC_CLASS_$_ScreenshotLogger" fullword ascii
		$c7 = "_OBJC_CLASS_$_Uploader" fullword ascii
		$c8 = "_OBJC_CLASS_$_UsageLogger" fullword ascii
		$c9 = "_OBJC_CLASS_$_WebsiteLogger" fullword ascii

	condition:
		uint16(0)==0xfacf and (2 of ($x*) or 2 of ($c*))
}
