rule HKTL_Python_sectools
{
	meta:
		description = "Detects code which uses the python lib sectools"
		author = "Arnim Rupp"
		date = "2023-01-27"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://github.com/p0dalirius/sectools"
		hash = "814ba1aa62bbb7aba886edae0f4ac5370818de15ca22a52a6ab667b4e93abf84"
		hash = "b3328ac397d311e6eb79f0a5b9da155c4d1987e0d67487ea681ea59d93641d9e"
		hash = "8cd205d5380278cff6673520439057e78fb8bf3d2b1c3c9be8463e949e5be4a1"
		score = 50
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$import1 = "from sectools"
		$import2 = "import sectools"

	condition:
		any of ($import*)
}
