import "pe"

rule MALWARE_Win_RedLineDropperEXE
{
	meta:
		author = "ditekSHen"
		description = "Detects executables dropping RedLine infostealer"
		clamav_sig = "MALWARE.Win.Trojan.RedLineDropper-EXE"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Wizutezinod togeto0Rowadufevomuki futenujilazem jic lefogatenezinor" fullword wide
		$s2 = "6Tatafamobevofaj bizafoju peyovavacoco lizine kezakajuj" fullword wide
		$s3 = "Lawuherusozeru kucu zam0Zorizeyuk lepaposupu gala kinarusot ruvasaxehuwo" fullword wide
		$s4 = "ClearEventLogW" fullword ascii
		$s5 = "ProductionVersion" fullword wide
		$s6 = "Vasuko)Yugenizugilobo toxocivoriye yexozoyohuzeb" wide
		$s7 = "Yikezevavuzus gucajanesan#Rolapucededoxu xewulep fuwehofiwifi" wide

	condition:
		uint16(0)==0x5a4d and (pe.exports("_fgeek@8") and 2 of them ) or (2 of them and for any i in (0..pe.number_of_sections) : ((pe.sections[i].name==".rig")))
}
