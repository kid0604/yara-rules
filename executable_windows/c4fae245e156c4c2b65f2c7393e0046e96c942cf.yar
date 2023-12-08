rule dubrute_alt_1 : bruteforcer toolkit
{
	meta:
		author = "Christian Rebischke (@sh1bumi)"
		date = "2015-09-05"
		description = "Rules for DuBrute Bruteforcer"
		in_the_wild = true
		family = "Hackingtool/Bruteforcer"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "WBrute"
		$b = "error.txt"
		$c = "good.txt"
		$d = "source.txt"
		$e = "bad.txt"
		$f = "Generator IP@Login;Password"

	condition:
		uint16(0)==0x5A4D and $a and $b and $c and $d and $e and $f
}
