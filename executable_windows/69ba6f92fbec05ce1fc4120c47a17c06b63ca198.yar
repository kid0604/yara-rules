import "pe"

rule WoolenGoldfish_Generic_1
{
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 90
		super_rule = 1
		hash0 = "5d334e0cb4ff58859e91f9e7f1c451ffdc7544c3"
		hash1 = "d5b2b30fe2d4759c199e3659d561a50f88a7fb2e"
		hash2 = "a42f1ad2360833baedd2d5f59354c4fc3820c475"
		os = "windows"
		filetype = "executable"

	strings:
		$x0 = "Users\\Wool3n.H4t\\"
		$x1 = "C-CPP\\CWoolger"
		$x2 = "NTSuser.exe" fullword wide
		$s1 = "107.6.181.116" fullword wide
		$s2 = "oShellLink.Hotkey = \"CTRL+SHIFT+F\"" fullword
		$s3 = "set WshShell = WScript.CreateObject(\"WScript.Shell\")" fullword
		$s4 = "oShellLink.IconLocation = \"notepad.exe, 0\"" fullword
		$s5 = "set oShellLink = WshShell.CreateShortcut(strSTUP & \"\\WinDefender.lnk\")" fullword
		$s6 = "wlg.dat" fullword
		$s7 = "woolger" fullword wide
		$s8 = "[Enter]" fullword
		$s9 = "[Control]" fullword

	condition:
		(1 of ($x*) and 2 of ($s*)) or (6 of ($s*))
}
