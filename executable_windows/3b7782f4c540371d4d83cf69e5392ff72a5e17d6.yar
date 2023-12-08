import "pe"

rule SUSP_APT_MAL_VEILEDSIGNAL_Backdoor_Apr23
{
	meta:
		description = "Detects marker found in VEILEDSIGNAL backdoor"
		author = "X__Junior"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		date = "2023-04-20"
		modified = "2023-04-21"
		score = 75
		hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"
		os = "windows"
		filetype = "executable"

	strings:
		$opb1 = { 81 BD ?? ?? ?? ?? 5E DA F3 76}
		$opb2 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA 66 C7 85 ?? ?? ?? ?? E5 CF}
		$opb3 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA B9 00 04 00 00 66 C7 85 ?? ?? ?? ?? E5 CF }

	condition:
		2 of them
}
