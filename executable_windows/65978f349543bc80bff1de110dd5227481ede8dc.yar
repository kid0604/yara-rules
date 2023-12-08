rule CN_Honker_sig_3389_DUBrute_v3_0_RC3_2_0
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 2.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e8ee982421ccff96121ffd24a3d84e3079f3750f"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
		$s3 = "Create %d IP@Loginl;Password" fullword ascii
		$s15 = "UBrute.com" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <980KB and 2 of them
}
