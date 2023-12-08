import "pe"

rule INDICATOR_EXE_Packed_DotNetReactor
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with unregistered version of .NET Reactor"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "is protected by an unregistered version of Eziriz's\".NET Reactor\"!" wide
		$s2 = "is protected by an unregistered version of .NET Reactor!\" );</script>" wide
		$s3 = "is protected by an unregistered version of Eziriz's \".NET Reactor\"!" wide

	condition:
		uint16(0)==0x5a4d and 1 of them
}
