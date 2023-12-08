rule Nirsoft_NetResView
{
	meta:
		description = "Detects NirSoft NetResView - utility that displays the list of all network resources"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 40
		hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "NetResView.exe" fullword wide
		$s2 = "2005 - 2013 Nir Sofer" wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
