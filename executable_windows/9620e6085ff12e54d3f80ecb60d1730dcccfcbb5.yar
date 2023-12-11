import "pe"

rule IMPLANT_4_v3_AlternativeRule
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		comment = "Alternative rule - not based on the original samples but samples on which the original rule matched"
		author = "Florian Roth"
		reference = "US CERT Grizzly Steppe Report"
		date = "2017-02-12"
		hash1 = "2244fe9c5d038edcb5406b45361613cf3909c491e47debef35329060b00c985a"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 33 c9 41 ff 13 13 c9 ff 13 72 f8 c3 53 1e 01 00 }
		$op2 = { 21 da 40 00 00 a0 40 00 08 a0 40 00 b0 70 40 00 }

	condition:
		( uint16(0)==0x5a4d and all of them )
}
