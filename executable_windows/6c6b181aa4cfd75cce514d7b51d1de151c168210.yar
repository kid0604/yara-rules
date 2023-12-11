rule DarkSpy105
{
	meta:
		description = "Webshells Auto-generated - file DarkSpy105.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f0b85e7bec90dba829a3ede1ab7d8722"
		os = "windows"
		filetype = "executable"

	strings:
		$s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!"

	condition:
		all of them
}
