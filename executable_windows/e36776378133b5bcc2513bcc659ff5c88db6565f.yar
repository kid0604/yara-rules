import "pe"

rule HiddenCobra_FallChill_1
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
		date = "2017-11-15"
		hash1 = "a606716355035d4a1ea0b15f3bee30aad41a2c32df28c2d468eafd18361d60d6"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "REGSVR32.EXE.MUI" fullword wide
		$s2 = "Microsoft Corporation. All rights reserved." fullword wide
		$s3 = "c%sd.e%sc %s > \"%s\" 2>&1" fullword wide
		$s4 = "\" goto Loop" fullword ascii
		$e1 = "xolhvhlxpvg" fullword ascii
		$e2 = "tvgslhgybmanv" fullword ascii
		$e3 = "CivagvTllosvok32Smakhslg" fullword ascii
		$e4 = "GvgCfiivmgDrivxglibW" fullword ascii
		$e5 = "OkvmPilxvhhTlpvm" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="6135d9bc3591ae7bc72d070eadd31755" or 3 of ($s*) or 4 of them )
}
