rule MacGyverCap : MacGyver
{
	meta:
		description = "Generic rule for MacGyver.cap"
		author = "xylitol@temari.fr"
		date = "2021-05-11"
		reference = "https://github.com/fboldewin/MacGyver-s-return---An-EMV-Chip-cloning-case/blob/master/MacGyver's%20return%20-%20An%20EMV%20Chip%20cloning%20case.pdf"
		hash1 = "9dc70002e82c78ee34c813597925c6cf8aa8d68b7e9ce5bcc70ea9bcab9dbf4a"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$string1 = "src/MacGyver/javacard/Header.cap" ascii wide
		$string2 = "src/MacGyver/javacard/Directory.cap" ascii wide
		$string3 = "src/MacGyver/javacard/Applet.cap" ascii wide
		$string4 = "src/MacGyver/javacard/Import.cap" ascii wide
		$string5 = "src/MacGyver/javacard/ConstantPool.cap" ascii wide
		$string6 = "src/MacGyver/javacard/Class.cap" ascii wide
		$string7 = "src/MacGyver/javacard/Method.cap" ascii wide

	condition:
		all of them
}
