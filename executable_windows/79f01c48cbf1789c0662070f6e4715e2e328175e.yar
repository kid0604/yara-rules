rule GoogleBot_UserAgent
{
	meta:
		description = "Detects the GoogleBot UserAgent String in an Executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-01-27"
		score = 65
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii
		$fp1 = "McAfee, Inc." wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and $x1 and not 1 of ($fp*))
}
