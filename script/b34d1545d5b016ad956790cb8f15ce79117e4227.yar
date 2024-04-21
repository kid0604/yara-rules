import "pe"

rule case_4778_launcher
{
	meta:
		description = "files - file launcher.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-15"
		hash1 = "d9e8440665f37ae16b60ba912c540ba1f689c8ef7454defbdbf6ce7d776b8e24"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "%oveqxh%%qvgs%%siksf%%dlxh%%mdiry%%bkpy%%eluai%%cnvepu%%gpwfty%%bkpy%%jvfkra%%irckvi%%gpxipg%%veoamv%%veqa%%obkpb%%bkpy%%gpuc%%u" ascii
		$s2 = "%oveqxh%%qvgs%%siksf%%dlxh%%mdiry%%bkpy%%eluai%%cnvepu%%gpwfty%%bkpy%%jvfkra%%irckvi%%gpxipg%%veoamv%%veqa%%obkpb%%bkpy%%gpuc%%u" ascii
		$s3 = "%nhmveo%%siksf%irckvi%aqvmr%d" fullword ascii
		$s4 = "bgobkp%%owing%%eqxo%%irckvi%%gobk%%gwcnve%%fryrww%%najafo%%cnvepu%%wgnvi%%amwen%%gpxipg%%pgpu%%cnvepu%" fullword ascii
		$s5 = "%nhmveo% siksf= " fullword ascii
		$s6 = "%nhmveo%%siksf%gpuc%aqvmr%Ap" fullword ascii
		$s7 = "%nhmveo%%siksf%aqvmr==" fullword ascii
		$s8 = "%nhmveo%%siksf%mdiry%aqvmr%:" fullword ascii
		$s9 = "%nhmveo%%siksf%gpxipg%aqvmr%." fullword ascii
		$s10 = "%nhmveo%%siksf%owing%aqvmr%7f" fullword ascii
		$s11 = "%nhmveo%%siksf%bgobkp%aqvmr%659" fullword ascii
		$s12 = "%nhmveo%%siksf%ygob%aqvmr%D" fullword ascii
		$s13 = "%nhmveo%%siksf%pgpu%aqvmr%ex" fullword ascii
		$s14 = "%nhmveo%%siksf%otmrb%aqvmr%l" fullword ascii
		$s15 = "%nhmveo%%siksf%wclsbn%aqvmr%iMe" fullword ascii
		$s16 = "%nhmveo%%siksf%qvgs%aqvmr%rt" fullword ascii
		$s17 = "%nhmveo%%siksf%udpwpu%aqvmr%pD" fullword ascii
		$s18 = "%nhmveo%%siksf%najafo%aqvmr%22c" fullword ascii
		$s19 = "%nhmveo%%siksf%fryrww%aqvmr%d4d" fullword ascii
		$s20 = "%nhmveo%%siksf%ensen%aqvmr%ee" fullword ascii

	condition:
		uint16(0)==0x6573 and filesize <4KB and 8 of them
}
