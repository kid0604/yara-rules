rule case_14373_bumblebee_document_iso
{
	meta:
		description = "Files - file document.iso"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/09/26/bumblebee-round-two/"
		date = "2022-09-26"
		hash1 = "11bce4f2dcdc2c1992fddefb109e3ddad384b5171786a1daaddadc83be25f355"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$x1 = "tamirlan.dll,EdHVntqdWt\"%systemroot%\\system32\\imageres.dll" fullword wide
		$s2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
		$s3 = "xotgug064ka8.dll" fullword ascii
		$s4 = "tamirlan.dll" fullword wide
		$s5 = ")..\\..\\..\\..\\Windows\\System32\\rundll32.exe" fullword wide
		$s6 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
		$s7 = "claims indebted fires plastic naturalist deduction meaningless yielded automatic wrote damage far use fairly allocation lever ne" ascii
		$s8 = "documents.lnk" fullword wide
		$s9 = "4System32" fullword wide
		$s10 = "\\_P^YVPX[SY]WT^^RQ_V[YQV\\Y]USUZV[XWT_SWT[UYURVVRVR^^[__XRQPPUXZWYYVU]V\\[TS[SSWWVY_R_Y[XZ_W[VVS\\]ZYSPYURUSP\\U^P^^S\\QVRQXPTV" ascii
		$s11 = "\\_P^YVPX[SY]WT^^RQ_V[YQV\\Y]USUZV[XWT_SWT[UYURVVRVR^^[__XRQPPUXZWYYVU]V\\[TS[SSWWVY_R_Y[XZ_W[VVS\\]ZYSPYURUSP\\U^P^^S\\QVRQXPTV" ascii
		$s12 = " Type Descriptor'" fullword ascii
		$s13 = "YP^WTS]V[WPTWR_\\P[]WX_SPYQ[SQ]]UWTU]QR\\UQR]]\\\\^]UZUX\\X^U]P_^S[ZY^R^]UXWZURR\\]X[^TX\\S\\SWV_[YXP_[^^\\WW\\]]]PU_YZ\\]SVPQX[" ascii
		$s14 = "494[/D59:" fullword ascii
		$s15 = "_ZQ\\V\\TW]P\\YW^_PZT_TR[T_WVQUSQPVSPYRSWPS^WVQR_[T_PS[]TT]RSSQV_[_Q]UY\\\\QPVQRXXPPR^_VSZRRRSWXTUV^PRQQXPSWPSWSYWWV^YR_Z]PWRP]^" ascii
		$s16 = "?+7,*6@24" fullword ascii
		$s17 = "67?.68@6.3=" fullword ascii
		$s18 = "*;+273++C" fullword ascii
		$s19 = "*:>?2-:E?@>5D+" fullword ascii
		$s20 = "UPVX]VWVQU[_^ZU[_W^[R^]SPQ[[VPRR]]Z[\\XVU^_TR[YPR\\PY]RXT[_RXSPYSWTU]PV_SWWUVU\\R_X_U_V[__UW[\\^YU[WTUXSURQ]QSUPTXVXZV]WRP[_XW]" fullword ascii

	condition:
		uint16(0)==0x0000 and filesize <8000KB and 1 of ($x*) and 4 of them
}
