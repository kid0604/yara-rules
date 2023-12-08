rule Hacktools_CN_Burst_Thecard
{
	meta:
		description = "Disclosed hacktool set - file Thecard.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "50b01ea0bfa5ded855b19b024d39a3d632bacb4c"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "tasklist |find \"Clear.bat\"||start Clear.bat" fullword ascii
		$s1 = "Http://www.coffeewl.com" fullword ascii
		$s2 = "ping -n 2 localhost 1>nul 2>nul" fullword ascii
		$s3 = "for /L %%a in (" fullword ascii
		$s4 = "MODE con: COLS=42 lines=5" fullword ascii

	condition:
		all of them
}
