rule FiveEyes_QUERTY_Malwaresig_20120_cmdDef
{
	meta:
		description = "FiveEyes QUERTY Malware - file 20120_cmdDef.xml"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "cda9ceaf0a39d6b8211ce96307302a53dfbd71ea"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "This PPC gets the current keystroke log." fullword ascii
		$s1 = "This command will add the given WindowTitle to the list of Windows to log keys f" ascii
		$s2 = "This command will remove the WindowTitle corresponding to the given window title" ascii
		$s3 = "This command will return the current status of the Keyboard Logger (Whether it i" ascii
		$s4 = "This command Toggles logging of all Keys. If allkeys is toggled all keystrokes w" ascii
		$s5 = "<definition>Turn logging of all keys on|off</definition>" fullword ascii
		$s6 = "<name>Get Keystroke Log</name>" fullword ascii
		$s7 = "<description>Keystroke Logger Lp Plugin</description>" fullword ascii
		$s8 = "<definition>display help for this function</definition>" fullword ascii
		$s9 = "This command will switch ON Logging of keys. All keys taht are entered to a acti" ascii
		$s10 = "Set the log limit (in number of windows)" fullword ascii
		$s11 = "<example>qwgetlog</example>" fullword ascii
		$s12 = "<aliasName>qwgetlog</aliasName>" fullword ascii
		$s13 = "<definition>The title of the Window whose keys you wish to Log once it becomes a" ascii
		$s14 = "This command will switch OFF Logging of keys. No keystrokes will be captured" fullword ascii
		$s15 = "<definition>The title of the Window whose keys you no longer whish to log</defin" ascii
		$s16 = "<command id=\"32\">" fullword ascii
		$s17 = "<command id=\"3\">" fullword ascii
		$s18 = "<command id=\"7\">" fullword ascii
		$s19 = "<command id=\"1\">" fullword ascii
		$s20 = "<command id=\"4\">" fullword ascii

	condition:
		10 of them
}
