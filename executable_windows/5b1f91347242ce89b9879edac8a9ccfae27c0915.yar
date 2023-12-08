import "pe"

rule MALWARE_Win_SimplePacker
{
	meta:
		author = "ditekSHen"
		description = "Detects Hydrochasma packer / dropper"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "\\cloud-compiler-" ascii
		$p2 = "\\deps\\simplepacker.pdb" ascii
		$s1 = "uespemosarenegylmodnarodsetybdetqueue" ascii
		$s2 = "None{\"" ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($p*) or (1 of ($p*) and all of ($s*)))
}
