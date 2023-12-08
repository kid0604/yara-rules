import "pe"

rule OilRig_Malware_Campaign_Gen3
{
	meta:
		description = "Detects Oilrig malware samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/QMRZ8K"
		date = "2016-10-12"
		modified = "2023-01-07"
		hash1 = "5e9ddb25bde3719c392d08c13a295db418d7accd25d82d020b425052e7ba6dc9"
		hash2 = "bd0920c8836541f58e0778b4b64527e5a5f2084405f73ee33110f7bc189da7a9"
		hash3 = "90639c7423a329e304087428a01662cc06e2e9153299e37b1b1c90f6d0a195ed"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "source code from https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.htmlrrrr" fullword ascii
		$x2 = "\\Libraries\\fireueye.vbs" ascii
		$x3 = "\\Libraries\\fireeye.vbs&" wide

	condition:
		( uint16(0)==0xcfd0 and filesize <100KB and 1 of them )
}
