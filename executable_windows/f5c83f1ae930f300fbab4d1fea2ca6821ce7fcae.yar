rule MAL_HawkEye_Keylogger_Gen_Dec18
{
	meta:
		description = "Detects HawkEye Keylogger Reborn"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/James_inthe_box/status/1072116224652324870"
		date = "2018-12-10"
		hash1 = "b8693e015660d7bd791356b352789b43bf932793457d54beae351cf7a3de4dad"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "HawkEye Keylogger" fullword wide
		$s2 = "_ScreenshotLogger" ascii
		$s3 = "_PasswordStealer" ascii

	condition:
		2 of them
}
