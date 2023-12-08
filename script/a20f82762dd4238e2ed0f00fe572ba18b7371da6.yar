rule sbin_squid
{
	meta:
		description = "Chinese Hacktool Set - file squid.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8b795a8085c3e6f3d764ebcfe6d59e26fdb91969"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "del /s /f /q" fullword ascii
		$s1 = "squid.exe -z" fullword ascii
		$s2 = "net start Squid" fullword ascii
		$s3 = "net stop Squid" fullword ascii

	condition:
		filesize <1KB and all of them
}
