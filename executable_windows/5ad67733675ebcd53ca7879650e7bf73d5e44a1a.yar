rule tick_ABK_pdb
{
	meta:
		description = "ABK downloader malware"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "fb0d86dd4ed621b67dced1665b5db576247a10d43b40752c1236be783ac11049"
		hash2 = "3c16a747badd3be70e92d10879eb41d4312158c447e8d462e2b30c3b02992f2a"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb3 = "C:\\Users\\Frank\\Desktop\\ABK\\Release\\Hidder.pdb"
		$pdb4 = "C:\\Users\\Frank\\Documents\\Visual Studio 2010\\Projects\\avenger\\Release\\avenger.pdb"
		$pdb5 = "C:\\Users\\Frank\\Desktop\\ABK\\Release\\ABK.pdb"

	condition:
		($pdb3 or $pdb4 or $pdb5) and uint16(0)==0x5A4D
}
