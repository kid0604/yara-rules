rule WMI_vbs : APT
{
	meta:
		description = "WMI Tool - APT"
		author = "Florian Roth"
		release_date = "2013-11-29"
		confidential = false
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$s3 = "WScript.Echo \"   $$\\      $$\\ $$\\      $$\\ $$$$$$\\ $$$$$$$$\\ $$\\   $$\\ $$$$$$$$\\  $$$$$$"

	condition:
		all of them
}
