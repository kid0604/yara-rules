rule screencap
{
	meta:
		description = "Webshells Auto-generated - file screencap.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "51139091dea7a9418a50f2712ea72aa6"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "GetDIBColorTable"
		$s1 = "Screen.bmp"
		$s2 = "CreateDCA"

	condition:
		all of them
}
