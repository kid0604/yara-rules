rule Payload_Exe2Hex
{
	meta:
		description = "Detects payload generated by exe2hex"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/g0tmi1k/exe2hex"
		date = "2016-01-15"
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "set /p \"=4d5a" ascii
		$a2 = "powershell -Command \"$hex=" ascii
		$b1 = "set+%2Fp+%22%3D4d5" ascii
		$b2 = "powershell+-Command+%22%24hex" ascii
		$c1 = "echo 4d 5a " ascii
		$c2 = "echo r cx >>" ascii
		$d1 = "echo+4d+5a+" ascii
		$d2 = "echo+r+cx+%3E%3E" ascii

	condition:
		all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*)
}
