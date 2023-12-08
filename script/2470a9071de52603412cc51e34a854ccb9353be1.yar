rule FSO_s_c99
{
	meta:
		description = "Webshells Auto-generated - file c99.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5f9ba02eb081bba2b2434c603af454d0"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce"

	condition:
		all of them
}
