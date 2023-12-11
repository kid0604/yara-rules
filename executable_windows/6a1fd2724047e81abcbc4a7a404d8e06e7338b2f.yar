rule OpCloudHopper_Malware_8
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "19aa5019f3c00211182b2a80dd9675721dac7cfb31d174436d3b8ec9f97d898b"
		hash2 = "5cebc133ae3b6afee27beb7d3cdb5f3d675c3f12b7204531f453e99acdaa87b1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WSHELL32.dll" fullword wide
		$s2 = "operator \"\" " fullword ascii
		$s3 = "\" /t REG_SZ /d \"" fullword wide
		$s4 = " /f /v \"" fullword wide
		$s5 = "zok]\\\\\\ZZYYY666564444" fullword ascii
		$s6 = "AFX_DIALOG_LAYOUT" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and 4 of them )
}
