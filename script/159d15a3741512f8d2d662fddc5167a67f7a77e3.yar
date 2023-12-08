rule CN_Honker_ASP_wshell
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wshell.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3ae33c835e7ea6d9df74fe99fcf1e2fb9490c978"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
		$s1 = "UserPass="
		$s2 = "VerName="
		$s3 = "StateName="

	condition:
		uint16(0)==0x253c and filesize <200KB and all of them
}
