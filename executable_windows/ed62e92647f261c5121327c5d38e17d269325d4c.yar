rule APT_Loader_Win_PGF_1_alt_4
{
	meta:
		description = "PDB string used in some PGF DLL samples"
		md5 = "013c7708f1343d684e3571453261b586"
		rev = 6
		author = "FireEye"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb1 = /RSDS[\x00-\xFF]{20}c:\\source\\dllconfig-master\\dllsource[\x00-\xFF]{0,500}\.pdb\x00/ nocase
		$pdb2 = /RSDS[\x00-\xFF]{20}C:\\Users\\Developer\\Source[\x00-\xFF]{0,500}\\Release\\DllSource\.pdb\x00/ nocase
		$pdb3 = /RSDS[\x00-\xFF]{20}q:\\objchk_win7_amd64\\amd64\\init\.pdb\x00/ nocase

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and filesize <15MB and any of them
}
