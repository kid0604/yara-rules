rule blazingtools
{
	meta:
		author = "@patrickrolsen"
		reference = "Blazing Tools - http://www.blazingtools.com (Keyloggers)"
		description = "Detects Blazing Tools keylogger"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "blazingtools.com"
		$s2 = "Keystrokes" wide
		$s3 = "Screenshots" wide

	condition:
		uint16(0)==0x5A4D and all of ($s*)
}
