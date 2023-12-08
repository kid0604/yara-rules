import "pe"

rule EnigmaProtector11X13XSukhovVladimirSergeNMarkin
{
	meta:
		author = "malware-lu"
		description = "Detects Enigma Protector 1.1X13X by Sukhov Vladimir Serge N Markin"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9 }

	condition:
		$a0
}
