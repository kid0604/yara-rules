import "pe"

rule TopHat_Malware_Jan18_2
{
	meta:
		description = "Auto-generated rule - file e.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-the-tophat-campaign-attacks-within-the-middle-east-region-using-popular-third-party-services/#appendix"
		date = "2018-01-29"
		modified = "2023-01-06"
		hash1 = "9580d15a06cd59c01c59bca81fa0ca8229f410b264a38538453f7d97bfb315e7"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii
		$s2 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" ascii
		$s3 = "LError loading dock zone from the stream. Expecting version %d, but found %d." fullword wide
		$s4 = "WINMGMTS:\\\\.\\ROOT\\CIMV2" fullword ascii
		$s5 = "UENCRYPTION" fullword ascii
		$s6 = "TEXPORTAPIS" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (pe.imphash()=="f98cebcae832abc3c46e6e296aecfc03" and 5 of them )
}
