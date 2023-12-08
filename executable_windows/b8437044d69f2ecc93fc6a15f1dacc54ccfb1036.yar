import "pe"

rule MALWARE_Win_BrowserGrabber
{
	meta:
		author = "ditekSHen"
		description = "Hunt for FOXGRABBER-like samples but for various browsers"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "start grabbing" wide
		$s2 = "end grabbing in" wide
		$s3 = "error of copying files from comp:" wide
		$s4 = /(Chrome|Edge)/ wide
		$ff = "\\Firefox\\" wide nocase
		$pdb1 = "\\obj\\Debug\\grab" ascii
		$pdb2 = "\\obj\\Release\\grab" ascii

	condition:
		uint16(0)==0x5a4d and not ($ff) and ( all of ($s*) or (1 of ($pdb*) and 1 of ($s*)))
}
