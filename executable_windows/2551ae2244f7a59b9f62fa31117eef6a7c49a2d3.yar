rule BlackTech_TSCookie_loader_pdb
{
	meta:
		description = "detect tscookie loader pdb"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "PE file search"
		hash1 = "cc424006225d4dfcb7a6287bccd9c338d570c733b5ffcbf77be8e23a4cc20f6e"
		hash2 = "794f942c3298a43712f873cc20882d8138f75105fb151f99c5802f91f884ef04"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb1 = "D:\\[0]MyATS-TEMP-Loading-"
		$pdb2 = "ATS-TEMP-Loader-"
		$pdb3 = "MyFuckers\\MyFuckers_"
		$pdb4 = "MyFuckersService8\\MyFuckers_"

	condition:
		uint16(0)==0x5A4D and ($pdb1 or $pdb2 or $pdb3 or $pdb4)
}
