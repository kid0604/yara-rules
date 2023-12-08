rule PowerShell_Emp_Eval_Jul17_A2
{
	meta:
		description = "Detects suspicious sample with PowerShell content "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "PowerShell Empire Eval"
		date = "2017-07-27"
		hash1 = "e14c139159c23fdc18969afe57ec062e4d3c28dd42a20bed8ddde37ab4351a51"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "\\support\\Release\\ab.pdb" ascii
		$s2 = "powershell.exe" ascii fullword

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
