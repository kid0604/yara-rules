rule Lazarus_npmLoader_dll
{
	meta:
		description = "npmLoaderDll using Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash = "b4c8c149005a43ae043038d4d62631dc1a0f57514c7cbf4f7726add7ec67981a"
		hash = "eb8756ace46662a031c1d2422a91f0725ea7c4de74bfff4fce2693e7967be16e"
		hash = "aec915753612bb003330ce7ffc67cfa9d7e3c12310f0ecfd0b7e50abf427989a"
		os = "windows"
		filetype = "executable"

	strings:
		$jnkcode = { 66 66 66 66 ?? ?? ?? ?? 00 00 00 00 00 }
		$enccode1 = { 81 E2 FF 03 00 00 41 81 E1 FF 03 00 00 81 E7 FF 03 00 00 81 E1 FF 03 00 00 }
		$enccode2 = { 48 33 D1 8B C1 41 C1 CA 0A C1 C0 09 81 E2 FF 03 00 00 44 33 D0 }
		$pdb1 = "F:\\workspace\\CBG\\Loader\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb" ascii wide
		$pdb2 = "F:\\workspace\\CBG\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb" ascii wide
		$pdb3 = "D:\\workspace\\CBG\\Windows\\Loader\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb" ascii wide
		$pdb4 = "npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb" ascii wide

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and ((1 of ($pdb*)) or ($jnkcode and all of ($enccode*)))
}
