import "pe"

rule PSAttack_EXE
{
	meta:
		description = "PSAttack - Powershell attack tool - file PSAttack.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/gdssecurity/PSAttack/releases/"
		date = "2016-03-09"
		modified = "2023-01-06"
		score = 100
		hash = "ad05d75640c850ee7eeee26422ba4f157be10a4e2d6dc6eaa19497d64cf23715"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Release\\PSAttack.pdb"
		$s1 = "set-executionpolicy bypass -Scope process -Force" fullword wide
		$s2 = "PSAttack.Modules." ascii
		$s3 = "PSAttack.PSAttackProcessing" fullword ascii
		$s4 = "PSAttack.Modules.key.txt" fullword wide

	condition:
		( uint16(0)==0x5a4d and ($x1 or 2 of ($s*))) or 3 of them
}
