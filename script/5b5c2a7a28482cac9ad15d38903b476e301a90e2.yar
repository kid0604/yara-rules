rule VBS_dropper_script_Dec17_1
{
	meta:
		description = "Detects a supicious VBS script that drops an executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-01-01"
		score = 80
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "TVpTAQEAAAAEAA"
		$s2 = "TVoAAAAAAAAAAA"
		$s3 = "TVqAAAEAAAAEAB"
		$s4 = "TVpQAAIAAAAEAA"
		$s5 = "TVqQAAMAAAAEAA"
		$a1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii

	condition:
		filesize <600KB and $a1 and 1 of ($s*)
}
