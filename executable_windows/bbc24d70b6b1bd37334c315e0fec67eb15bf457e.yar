import "pe"

rule ccrewMiniasp
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects the presence of MiniAsp.pdb and device_t in files related to CommentCrew threat APT1"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "MiniAsp.pdb" wide ascii
		$b = "device_t=" wide ascii

	condition:
		any of them
}
