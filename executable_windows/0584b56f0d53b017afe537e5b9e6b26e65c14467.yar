import "pe"

rule EquationGroup_pwdump_Lp
{
	meta:
		description = "EquationGroup Malware - file pwdump_Lp.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "fda57a2ba99bc610d3ff71b2d0ea2829915eabca168df99709a8fdd24288c5e5"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "PWDUMP - - ERROR - -" wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
