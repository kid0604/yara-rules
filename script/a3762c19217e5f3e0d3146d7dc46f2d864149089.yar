rule nstview_nstview
{
	meta:
		description = "Webshells Auto-generated - file nstview.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3871888a0c1ac4270104918231029a56"
		os = "linux"
		filetype = "script"

	strings:
		$s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");"

	condition:
		all of them
}
