rule PowerShell_Emp_Eval_Jul17_A1
{
	meta:
		description = "Detects suspicious sample with PowerShell content "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "PowerShell Empire Eval"
		date = "2017-07-27"
		hash1 = "4d10e80c7c80ef040efc680424a429558c7d76a965685bbc295908cb71137eba"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "powershell" wide
		$s2 = "pshcmd" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and all of them )
}
