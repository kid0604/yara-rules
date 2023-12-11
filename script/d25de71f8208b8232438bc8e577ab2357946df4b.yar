rule Fusion
{
	meta:
		description = "Detect the risk of Ransomware Nemty Rule 1"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "main.getdrives" ascii wide
		$s2 = "main.SaveNote" ascii wide
		$s3 = "main.FileSearch" ascii wide
		$s4 = "main.BytesToPublicKey" ascii wide
		$s5 = "main.GenerateRandomBytes" ascii wide
		$x1 = /Fa[i1]led to fi.Close/ ascii wide
		$x2 = /Fa[i1]led to fi2.Close/ ascii wide
		$x3 = /Fa[i1]led to get stat/ ascii wide
		$x4 = /Fa[i1]led to os.OpenFile/ ascii wide
		$pdb1 = "C:/OpenServer/domains/build/aes.go" ascii wide
		$pdb2 = "C:/Users/eugene/Desktop/test go/test.go" ascii wide
		$pdb3 = "C:/Users/eugene/Desktop/web/src/aes_" ascii wide

	condition:
		4 of ($s*) or 3 of ($x*) or any of ($pdb*)
}
