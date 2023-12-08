import "pe"

rule MALWARE_Win_DLInjector07
{
	meta:
		author = "ditekSHen"
		description = "Detects downloader injector"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "23lenrek[||]lldtn[||]daerhTemuseR[||]txetnoCdaerhTteS46woW[||]txetnoCdaerhTteS[||]txetnoCdaerhTteG46woW[||]txetnoCdaerhTteG[||]xEcollAlautriV[||]yromeMssecorPetirW[||]yromeMssecorPdaeR[||]noitceSfOweiVpamnUwZ[||]AssecorPetaerC" wide
		$l1 = "[||]" wide
		$r1 = "yromeMssecorPetirW" wide
		$r2 = "xEcollAlautriV" wide
		$r3 = "daerhTemuseR" ascii wide
		$r4 = "noitceSfOweiVpamnUwZ" wide
		$s1 = "Debugger Detected" fullword wide
		$s2 = "payload" fullword ascii
		$s3 = "_ENABLE_PROFILING" fullword wide

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or (1 of ($l*) and 2 of ($r*)) or 6 of them )
}
