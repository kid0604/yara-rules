rule Win_PrivEsc_gp3finder_v4_0
{
	meta:
		description = "Detects a tool that can be used for privilege escalation - file gp3finder_v4.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder/"
		date = "2016-06-02"
		score = 80
		hash1 = "7d34e214ef2ca33516875fb91a72d5798f89b9ea8964d3990f99863c79530c06"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Check for and attempt to decrypt passwords on share" ascii
		$x2 = "Failed to auto get and decrypt passwords. {0}s/" fullword ascii
		$x3 = "GPPPFinder - Group Policy Preference Password Finder" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 1 of ($x*)) or ( all of them )
}
