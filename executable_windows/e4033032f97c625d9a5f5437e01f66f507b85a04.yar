rule gozi_17386_itsIt_db
{
	meta:
		description = "Gozi - file itsIt.db"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "60375d64a9a496e220b6eb1b63e899b3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "EoJA1.dll" fullword
		$s2 = "AXMsDQbUbhdpHgumy" fullword
		$s3 = "DllRegisterServer" fullword
		$s4 = "DqvdfVJXumSGuxDbQeifDE" fullword
		$s5 = "GsvFugemhLmFRebByHWZLIlt" fullword
		$s6 = "IBDFzyzaYYbvLCdANNWobWzkHefitgP" fullword
		$s7 = "KWwSSdVAwGpuPZJemC" fullword
		$s8 = "LRZeayHLHiLXcxFjinEZmyaMXWpoF" fullword
		$s9 = "LcVopTSimzPyMznceIIepGGLs" fullword
		$s10 = "OkJXHEIxVkZenNREJnYdhtufvRv" fullword
		$s11 = "OtsltXyqwGKmKSYm" fullword
		$s12 = "OvzfwfDhXuXhLmzEvnwCNPcfYAodAip" fullword
		$s13 = "QQASfqqFsaIyuodrOEzmiYhXFBhK" fullword
		$s14 = "RNsFxmZdRyUXEpddwSgBPDKQPQW" fullword
		$s15 = "RxfeQKNVUecCmdLsHQAGMbqVDxDAR" fullword
		$s16 = "SKRXxPrnvmLVjzGDJ" fullword
		$s17 = "UOGamDxqKzMifBHNcnBjIecgOy" fullword
		$s18 = "VHPqYBENjtlIcAUDdVEHyQrPsRjrWb" fullword
		$s19 = "VHYmMulTaXxJkuTCbDpFOCoWjdFipiT" fullword
		$s20 = "WJkBmOWdIlTJWBXfKCLRluK" fullword
		$s21 = "YIskifvVtpCHTPVefoogyKpjNpKk" fullword
		$s22 = "YqnsziMxolCUEpCyF" fullword
		$s23 = "aHjfpBCMGTOHtAxeJeqvYJiJipIc" fullword
		$s24 = "btmXEDkzSVQrIekKBbgAyAjFzB" fullword
		$s25 = "iZwERsKOdaNkDjJUj" fullword
		$s26 = "ifNYULjNknlPOsikeeFKq" fullword
		$s27 = "jZTjetqmFfnLpMHfBmKFXSWNjK" fullword
		$s28 = "kxNmMsXFaSQwVCttBDpieAV" fullword
		$s29 = "phDeNsVAkciNIDphsSICKbhrF" fullword
		$s30 = "srJhGTXYGHCFyCLmlYgSpAB" fullword
		$s31 = "tvMVzGtbiBFVgcrXhUsAKAuKQXi" fullword
		$s32 = "vowTIpYzkeDnPYtsuRYfGIGg" fullword
		$s33 = "GCTL" fullword

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
