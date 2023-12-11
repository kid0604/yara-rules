import "pe"

rule Equation_Kaspersky_GreyFishInstaller
{
	meta:
		description = "Equation Group Malware - Grey Fish"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "DOGROUND.exe" fullword wide
		$s1 = "Windows Configuration Services" fullword wide
		$s2 = "GetMappedFilenameW" fullword ascii

	condition:
		all of them
}
