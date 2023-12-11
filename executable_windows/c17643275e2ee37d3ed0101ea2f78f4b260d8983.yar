import "pe"

rule EquationGroup_pwdump_Implant
{
	meta:
		description = "EquationGroup Malware - file pwdump_Implant.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "dfd5768a4825d1c7329c2e262fde27e2b3d9c810653585b058fcf9efa9815964"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".?AVFeFinallyFailure@@" fullword ascii
		$s8 = ".?AVFeFinallySuccess@@" fullword ascii
		$s3 = "\\system32\\win32k.sys" wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
