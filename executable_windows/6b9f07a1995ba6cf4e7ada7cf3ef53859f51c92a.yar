rule Lazarus_VSingle_strings
{
	meta:
		description = "VSingle malware in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "b114b1a6aecfe6746b674f1fdd38a45d9a6bb1b4eb0b0ca2fdb270343f7c7332"
		hash2 = "63fa8ce7bf7c8324ed16c297092e1b1c5c0a0f8ab7f583ab16aa86a7992193e6"
		os = "windows"
		filetype = "executable"

	strings:
		$encstr1 = "Valefor was uninstalled successfully." ascii wide
		$encstr2 = "Executable Download Parameter Error" ascii wide
		$encstr3 = "Plugin Execute Result" ascii wide
		$pdb = "G:\\Valefor\\Valefor_Single\\Release\\VSingle.pdb" ascii
		$str1 = "sonatelr" ascii
		$str2 = ".\\mascotnot" ascii
		$str3 = "%s_main" ascii
		$str4 = "MigMut" ascii
		$str5 = "lkjwelwer" ascii
		$str6 = "CreateNamedPipeA finished with Error-%d" ascii
		$str7 = ".\\pcinpae" ascii
		$str8 = { C6 45 80 4C C6 45 81 00 C6 45 82 00 C6 45 83 00 C6 45 84 01 C6 45 85 14 C6 45 86 02 C6 45 87 00 }
		$xorkey1 = "o2pq0qy4ymcrbe4s" ascii wide
		$xorkey2 = "qwrhcd4pywuyv2mw" ascii wide
		$xorkey3 = "3olu2yi3ynwlnvlu" ascii wide
		$xorkey4 = "uk0wia0uy3fl3uxd" ascii wide

	condition:
		all of ($encstr*) or $pdb or 1 of ($xorkey*) or 3 of ($str*)
}
