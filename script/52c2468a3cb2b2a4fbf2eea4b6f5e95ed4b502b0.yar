rule JavaScript_Run_Suspicious
{
	meta:
		description = "Detects a suspicious Javascript Run command"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/craiu/status/900314063560998912"
		score = 60
		date = "2017-08-23"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "w = new ActiveXObject(" ascii
		$s2 = " w.Run(r);" fullword ascii

	condition:
		all of them
}
