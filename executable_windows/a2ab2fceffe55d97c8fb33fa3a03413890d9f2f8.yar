rule Gen_Base64_EXE : HIGHVOL
{
	meta:
		description = "Detects Base64 encoded Executable in Executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-04-21"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" wide ascii
		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" wide ascii
		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" wide ascii
		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" wide ascii
		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii
		$fp1 = "BAM Management class library"

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and 1 of ($s*) and not 1 of ($fp*)
}
