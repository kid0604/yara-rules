rule phpbackdoor15_php
{
	meta:
		description = "Semi-Auto-generated  - file phpbackdoor15.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0fdb401a49fc2e481e3dfd697078334b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na"
		$s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI"
		$s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s"

	condition:
		1 of them
}
