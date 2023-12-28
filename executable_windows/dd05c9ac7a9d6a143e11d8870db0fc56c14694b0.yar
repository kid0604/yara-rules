rule tick_SKYSEA_downloader
{
	meta:
		description = "Malware downloaded using a vulnerability in SKYSEA"
		author = "JPCERT/CC Incident Response Group"
		hash = "3955d0340ff6e625821de294acef4bdc0cc7b49606a984517cd985d0aac130a3"
		os = "windows"
		filetype = "executable"

	strings:
		$sa = "c:\\Projects\\vs2013\\phc-tools\\Release\\loader.pdb"
		$sb = "%s\\config\\.regeditKey.rc"

	condition:
		all of them
}
