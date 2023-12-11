import "pe"

rule APT_GreyEnergy_Malware_Oct18_5
{
	meta:
		description = "Detects samples from Grey Energy report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
		date = "2018-10-17"
		hash1 = "037723bdb9100d19bf15c5c21b649db5f3f61e421e76abe9db86105f1e75847b"
		hash2 = "b602ce32b7647705d68aedbaaf4485f1a68253f8f8132bd5d5f77284a6c2d8bb"
		os = "windows"
		filetype = "executable"

	strings:
		$s12 = "WespySSld.eQ" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 1 of them
}
