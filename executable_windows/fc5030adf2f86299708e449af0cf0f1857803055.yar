import "pe"

rule Reflective_DLL_Loader_Aug17_4
{
	meta:
		description = "Detects Reflective DLL Loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-08-20"
		hash1 = "205b881701d3026d7e296570533e5380e7aaccaa343d71b6fcc60802528bdb74"
		hash2 = "f76151646a0b94024761812cde1097ae2c6d455c28356a3db1f7905d3d9d6718"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "<H1>&nbsp;>> >> >> Keylogger Installed - %s %s << << <<</H1>" fullword ascii
		$s1 = "<H3> ----- Running Process ----- </H3>" fullword ascii
		$s2 = "<H2>Operating system: %s<H2>" fullword ascii
		$s3 = "<H2>System32 dir:  %s</H2>" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 2 of them )
}
