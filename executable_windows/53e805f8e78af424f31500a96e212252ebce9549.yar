import "pe"

rule EquationGroup_modifyAudit_Lp
{
	meta:
		description = "EquationGroup Malware - file modifyAudit_Lp.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "2a1f2034e80421359e3bf65cbd12a55a95bd00f2eb86cf2c2d287711ee1d56ad"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Read of audit related process memory failed" fullword wide
		$s2 = "** This may indicate that another copy of modify_audit is already running **" fullword wide
		$s3 = "Pattern match of code failed" fullword wide
		$s4 = "Base for necessary auditing dll not found" fullword wide
		$s5 = "Security auditing has been disabled" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 3 of them ) or ( all of them )
}
