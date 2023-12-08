import "pe"

rule HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1
{
	meta:
		description = "Detects Mimikatz SkeletonKey in Memory"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/sbousseaden/status/1292143504131600384?s=12"
		date = "2020-08-09"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = { 60 ba 4f ca c7 44 24 34 dc 46 6c 7a c7 44 24 38 
              03 3c 17 81 c7 44 24 3c 94 c0 3d f6 }

	condition:
		1 of them
}
