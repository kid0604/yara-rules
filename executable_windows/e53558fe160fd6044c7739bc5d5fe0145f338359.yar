rule tick_DALBOT_strings
{
	meta:
		description = "DALBOT malware"
		author = "JPCERT/CC Incident Response Group"
		hash = "4092c39282921a8884f5ce3d85fb1f2045323dba2a98332499fdd691fe4b8488"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb = "C:\\Users\\jack\\Documents\\Visual Studio 2010\\down_new\\Release\\down_new.pdb"
		$message = "CreatePipe(cmd) failed!!!"
		$url = "&uc=go"

	condition:
		$pdb or ($message and $url)
}
