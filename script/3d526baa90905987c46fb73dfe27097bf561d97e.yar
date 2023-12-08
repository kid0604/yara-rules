rule HawkEye_PHP_Panel
{
	meta:
		description = "Detects HawkEye Keyloggers PHP Panel"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/12/14"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$fname = $_GET['fname'];" ascii fullword
		$s1 = "$data = $_GET['data'];" ascii fullword
		$s2 = "unlink($fname);" ascii fullword
		$s3 = "echo \"Success\";" fullword ascii

	condition:
		all of ($s*) and filesize <600
}
