rule SUSP_EXPL_OBFUSC_Dec21_1
{
	meta:
		description = "Detects obfuscation methods used to evade detection in log4j exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/testanull/status/1469549425521348609"
		date = "2021-12-11"
		modified = "2022-11-08"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$f1 = { 24 7B 6C 6F 77 65 72 3A ?? 7D }
		$f2 = { 24 7B 75 70 70 65 72 3A ?? 7D }
		$x3 = "$%7blower:"
		$x4 = "$%7bupper:"
		$x5 = "%24%7bjndi:"
		$x6 = "$%7Blower:"
		$x7 = "$%7Bupper:"
		$x8 = "%24%7Bjndi:"
		$fp1 = "<html"

	condition:
		(1 of ($x*) or filesize <200KB and 1 of ($f*)) and not 1 of ($fp*)
}
