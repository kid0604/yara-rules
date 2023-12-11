import "pe"

rule MAL_Winnti_BR_Report_MockingJay
{
	meta:
		description = "Detects Winnti samples"
		author = "@br_data repo"
		reference = "https://github.com/br-data/2019-winnti-analyse"
		date = "2019-07-24"
		os = "windows"
		filetype = "executable"

	strings:
		$load_magic = { C7 44 ?? ?? FF D8 FF E0 }
		$iter = { E9 EA EB EC ED EE EF F0 }
		$jpeg = { FF D8 FF E0 00 00 00 00 00 00 }

	condition:
		uint16(0)==0x5a4d and $jpeg and ($load_magic or $iter in (@jpeg[1]..@jpeg[1]+200)) and for any i in (1..#jpeg) : ( uint8(@jpeg[i]+11)!=0)
}
