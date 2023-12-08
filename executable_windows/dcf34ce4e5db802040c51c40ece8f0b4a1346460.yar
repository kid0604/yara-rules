rule FiveEyes_QUERTY_Malwaresig_20120_dll
{
	meta:
		description = "FiveEyes QUERTY Malware - file 20120.dll.bin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "6811bfa3b8cda5147440918f83c40237183dbd25"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\QwLog_%d-%02d-%02d-%02d%02d%02d.txt" wide
		$s1 = "\\QwLog_%d-%02d-%02d-%02d%02d%02d.xml" wide
		$s2 = "Failed to send the EQwerty_driverStatusCommand to the implant." fullword ascii
		$s3 = "- Log Used (number of windows) - %d" fullword wide
		$s4 = "- Log Limit (number of windows) - %d" fullword wide
		$s5 = "Process or User Default Language" fullword wide
		$s6 = "Windows 98/Me, Windows NT 4.0 and later: Vietnamese" fullword wide
		$s7 = "- Logging of keystrokes is switched ON" fullword wide
		$s8 = "- Logging of keystrokes is switched OFF" fullword wide
		$s9 = "Qwerty is currently logging active windows with titles containing the fo" wide
		$s10 = "Windows 95, Windows NT 4.0 only: Korean (Johab)" fullword wide
		$s11 = "FAILED to get Qwerty Status" fullword wide
		$s12 = "- Successfully retrieved Log from Implant." fullword wide
		$s13 = "- Logging of all Windows is toggled ON" fullword wide
		$s14 = "- Logging of all Windows is toggled OFF" fullword wide
		$s15 = "Qwerty FAILED to retrieve window list." fullword wide
		$s16 = "- UNSUCCESSFUL Log Retrieval from Implant." fullword wide
		$s17 = "The implant failed to return a valid status" fullword ascii
		$s18 = "- Log files were NOT generated!" fullword wide
		$s19 = "Windows 2000/XP: Armenian. This is Unicode only." fullword wide
		$s20 = "- This machine is using a PS/2 Keyboard - Continue on using QWERTY" fullword wide

	condition:
		10 of them
}
