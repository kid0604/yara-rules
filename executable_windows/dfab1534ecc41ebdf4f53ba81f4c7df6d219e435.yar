rule Casper_Backdoor_x86
{
	meta:
		description = "Casper French Espionage Malware - Win32/ProxyBot.B - x86 Payload http://goo.gl/VRJNLo"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/VRJNLo"
		date = "2015-03-05"
		modified = "2023-01-27"
		hash = "f4c39eddef1c7d99283c7303c1835e99d8e498b0"
		score = 80
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\"svchost.exe\"" fullword wide
		$s2 = "firefox.exe" fullword ascii
		$s3 = "\"Host Process for Windows Services\"" fullword wide
		$x1 = "\\Users\\*" ascii
		$x2 = "\\Roaming\\Mozilla\\Firefox\\Profiles\\*" ascii
		$x3 = "\\Mozilla\\Firefox\\Profiles\\*" ascii
		$x4 = "\\Documents and Settings\\*" ascii
		$y1 = "%s; %S=%S" fullword wide
		$y2 = "%s; %s=%s" fullword ascii
		$y3 = "Cookie: %s=%s" fullword ascii
		$y4 = "http://%S:%d" fullword wide
		$z1 = "http://google.com/" ascii
		$z2 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" fullword ascii
		$z3 = "Operating System\"" fullword wide

	condition:
		( filesize <250KB and all of ($s*)) or (3 of ($x*) and 2 of ($y*) and 2 of ($z*))
}
