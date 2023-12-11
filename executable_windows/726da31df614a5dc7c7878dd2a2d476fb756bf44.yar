import "pe"

rule MAL_Trickbot_Oct19_2
{
	meta:
		description = "Detects Trickbot malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-10-02"
		hash1 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
		hash2 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\Users\\User\\Desktop\\Encrypt\\Math_Cad\\Release\\Math_Cad.pdb" fullword ascii
		$x2 = "AxedWV3OVTFfnGb" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <=2000KB and 1 of them
}
