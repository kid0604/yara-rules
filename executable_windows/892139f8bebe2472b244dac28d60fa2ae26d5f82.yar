import "pe"

rule APT_DarkHydrus_Jul18_1
{
	meta:
		description = "Detects strings found in malware samples in APT report in DarkHydrus"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
		date = "2018-07-28"
		hash1 = "99541ab28fc3328e25723607df4b0d9ea0a1af31b58e2da07eff9f15c4e6565c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Z:\\devcenter\\aggressor\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="d3666d1cde4790b22b44ec35976687fb" or 1 of them )
}
