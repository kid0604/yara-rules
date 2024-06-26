rule case_14373_bumblebee_tamirlan_dll
{
	meta:
		description = "Files - file tamirlan.dll"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/09/26/bumblebee-round-two/"
		date = "2022-09-26"
		hash1 = "123f96ff0a583d507439f79033ba4f5aa28cf43c5f2c093ac2445aaebdcfd31b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "xotgug064ka8.dll" fullword ascii
		$s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
		$s3 = "claims indebted fires plastic naturalist deduction meaningless yielded automatic wrote damage far use fairly allocation lever ne" ascii
		$s4 = "\\_P^YVPX[SY]WT^^RQ_V[YQV\\Y]USUZV[XWT_SWT[UYURVVRVR^^[__XRQPPUXZWYYVU]V\\[TS[SSWWVY_R_Y[XZ_W[VVS\\]ZYSPYURUSP\\U^P^^S\\QVRQXPTV" ascii
		$s5 = "\\_P^YVPX[SY]WT^^RQ_V[YQV\\Y]USUZV[XWT_SWT[UYURVVRVR^^[__XRQPPUXZWYYVU]V\\[TS[SSWWVY_R_Y[XZ_W[VVS\\]ZYSPYURUSP\\U^P^^S\\QVRQXPTV" ascii
		$s6 = " Type Descriptor'" fullword ascii
		$s7 = "YP^WTS]V[WPTWR_\\P[]WX_SPYQ[SQ]]UWTU]QR\\UQR]]\\\\^]UZUX\\X^U]P_^S[ZY^R^]UXWZURR\\]X[^TX\\S\\SWV_[YXP_[^^\\WW\\]]]PU_YZ\\]SVPQX[" ascii
		$s8 = "494[/D59:" fullword ascii
		$s9 = "_ZQ\\V\\TW]P\\YW^_PZT_TR[T_WVQUSQPVSPYRSWPS^WVQR_[T_PS[]TT]RSSQV_[_Q]UY\\\\QPVQRXXPPR^_VSZRRRSWXTUV^PRQQXPSWPSWSYWWV^YR_Z]PWRP]^" ascii
		$s10 = "?+7,*6@24" fullword ascii
		$s11 = "67?.68@6.3=" fullword ascii
		$s12 = "*;+273++C" fullword ascii
		$s13 = "*:>?2-:E?@>5D+" fullword ascii
		$s14 = "UPVX]VWVQU[_^ZU[_W^[R^]SPQ[[VPRR]]Z[\\XVU^_TR[YPR\\PY]RXT[_RXSPYSWTU]PV_SWWUVU\\R_X_U_V[__UW[\\^YU[WTUXSURQ]QSUPTXVXZV]WRP[_XW]" fullword ascii
		$s15 = "YX\\^SPP^XW_^^_Y]ZY[T_UQU_QXP[SV^RT_ZRPV\\YVVYPVR^UP^QYQXV^\\]]T_SQQR_ZSQZT_Y^^_]Z]QYW\\Z_T_VRTWQZPS\\X\\_]W]PTTSP\\[]WVSRR\\Q]Q" ascii
		$s16 = "Z_VV\\PSYWUT_Z\\WQSPY\\ZZ\\PY]W][RW^\\^ZPUZV[WZ\\QU_V[YU\\X[Q__\\YQQPZ[VR\\QUZUQVQ^PUPUXWQ_ZTRTZU[T^QUZ[UZRVYV\\^WRY_SR_YUUY_[]S" ascii
		$s17 = "R_XUSP^T[RVXUR_\\VU\\Y[YWV\\WYXV\\SQ_RU][R\\ZTU\\PWYQ[ZSRTQUZ]\\WSPY\\P[_]TX]YZPTSSZ[VXW[YT\\W\\Z[SXRYZYQ^PR^VZVU^VRV][RR]S\\V__" ascii
		$s18 = "Z_VV\\PSYWUT_Z\\WQSPY\\ZZ\\PY]W][RW^\\^ZPUZV[WZ\\QU_V[YU\\X[Q__\\YQQPZ[VR\\QUZUQVQ^PUPUXWQ_ZTRTZU[T^QUZ[UZRVYV\\^WRY_SR_YUUY_[]S" ascii
		$s19 = "PQP]^__\\ZZUSZYT_^S_SPPV]\\XPT_TPQU\\VWZQYZPZ^]]SW]R^[WYP]^[[R_RTSPYW^WU^QVPZ" fullword ascii
		$s20 = "Y]_QU\\ZQQSXRX[SPYVRWXU^P[VSSWUR]]PSWV\\X]Y[PX_UZ_PPP[WQVXY^^]^RRSPZ]^XWV^]" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 8 of them
}
