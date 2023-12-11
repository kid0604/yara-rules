import "pe"

rule IMPLANT_10_v2
{
	meta:
		description = "CozyDuke / CozyCar / CozyBear Implant by APT29"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$xor = { 34 ?? 66 33 C1 48 FF C1 }
		$nop = { 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00}

	condition:
		uint16(0)==0x5A4D and $xor and $nop
}
