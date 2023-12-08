rule Malicious_BAT_Strings
{
	meta:
		description = "Detects a string also used in Netwire RAT auxilliary"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		reference = "https://pastebin.com/8qaiyPxs"
		date = "2018-01-05"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "call :deleteSelf&exit /b"

	condition:
		filesize <600KB and 1 of them
}
