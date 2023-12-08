rule crack_Loader
{
	meta:
		description = "Auto-generated rule on file Loader.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "f4f79358a6c600c1f0ba1f7e4879a16d"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "NeoWait.exe"
		$s1 = "RRRRRRRW"

	condition:
		all of them
}
