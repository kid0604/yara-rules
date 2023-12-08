import "pe"

rule EquationGroup_RunAsChild_Lp
{
	meta:
		description = "EquationGroup Malware - file RunAsChild_Lp.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "1097e1d562341858e241f1f67788534c0e340a2dc2e75237d57e3f473e024464"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Privilege elevation failed" fullword wide
		$s2 = "Unable to open parent process" fullword wide
		$s4 = "Invalid input to lpRunAsChildPPC" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
