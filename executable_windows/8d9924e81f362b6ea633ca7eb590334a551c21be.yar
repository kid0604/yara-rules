rule OpCloudHopper_Malware_5
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "beb1bc03bb0fba7b0624f8b2330226f8a7da6344afd68c5bc526f9d43838ef01"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "CWINDOWSSYSTEMROOT" fullword ascii
		$x2 = "YJ_D_KROPOX_M_NUJI_OLY_S_JU_MOOK" fullword ascii
		$x3 = "NJK_JK_SED_PNJHGFUUGIOO_PIY" fullword ascii
		$x4 = "c_VDGQBUl}YSB_C_VDlqSDYFU" fullword ascii
		$s7 = "FALLINLOVE" fullword ascii
		$op1 = { 83 ec 60 8d 4c 24 00 e8 6f ff ff ff 8d 4c 24 00 }

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 2 of them )) or (4 of them )
}
