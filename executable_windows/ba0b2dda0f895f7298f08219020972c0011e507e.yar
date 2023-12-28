rule tick_DALBOTDRPR_strings
{
	meta:
		description = "DALBOT dropper malware"
		author = "JPCERT/CC Incident Response Group"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb = "C:\\Users\\jack\\Documents\\Visual Studio 2010\\down_new\\Release\\down_new.pdb"
		$comment = "CreatePipe(cmd) failed!!!"
		$mac = "%.2x%.2x%.2x%.2x%.2x%.2x"
		$aacmd = "AAAAA"

	condition:
		$pdb or ($comment and $mac and $aacmd)
}
