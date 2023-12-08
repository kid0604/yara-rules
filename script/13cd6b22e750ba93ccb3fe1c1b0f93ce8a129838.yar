rule sql1433_Start
{
	meta:
		description = "Chinese Hacktool Set - file Start.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "bd4be10f4c3a982647b2da1a8fb2e19de34eaf01"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s2 = "start creck.bat" fullword ascii
		$s3 = "del s1.txt" fullword ascii
		$s4 = "del Result.txt" fullword ascii
		$s5 = "del s.TXT" fullword ascii
		$s6 = "mode con cols=48 lines=20" fullword ascii

	condition:
		filesize <1KB and 2 of them
}
