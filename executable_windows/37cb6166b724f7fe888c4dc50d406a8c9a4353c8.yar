import "pe"

rule MALWARE_Win_WarzoneRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects AveMaria/WarzoneRAT"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "RDPClip" fullword wide
		$s2 = "Grabber" fullword wide
		$s3 = "Ave_Maria Stealer OpenSource" wide
		$s4 = "\\MidgetPorn\\workspace\\MsgBox.exe" wide
		$s5 = "@\\cmd.exe" wide
		$s6 = "/n:%temp%\\ellocnak.xml" wide
		$s7 = "Hey I'm Admin" wide
		$s8 = "warzone160" fullword ascii

	condition:
		uint16(0)==0x5a4d and 5 of ($s*)
}
