rule hkshell_hkshell
{
	meta:
		description = "Webshells Auto-generated - file hkshell.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "168cab58cee59dc4706b3be988312580"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PrSessKERNELU"
		$s2 = "Cur3ntV7sion"
		$s3 = "Explorer8"

	condition:
		all of them
}
