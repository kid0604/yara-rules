import "pe"

rule PasswordPro_NTLM_DLL
{
	meta:
		description = "Auto-generated rule - file NTLM.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "PasswordPro"
		date = "2017-08-27"
		hash1 = "47d4755d31bb96147e6230d8ea1ecc3065da8e557e8176435ccbcaea16fe50de"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "NTLM.dll" fullword ascii
		$s2 = "Algorithm: NTLM" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and pe.exports("GetHash") and pe.exports("GetInfo") and ( all of them ))
}
