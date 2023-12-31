rule EXP_Libre_Office_CVE_2018_16858
{
	meta:
		description = "RCE in Libre Office with crafted ODT file (CVE-2018-16858)"
		author = "John Lambert @JohnLaTwC / modified by Florian Roth"
		date = "2019-02-01"
		reference = "https://insert-script.blogspot.com/2019/02/libreoffice-cve-2018-16858-remote-code.html"
		hash = "95a02b70c117947ff989e3e00868c2185142df9be751a3fefe21f18fa16a1a6f"
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$s1 = "xlink:href=\"vnd.sun.star.script:" ascii nocase
		$s2 = ".py$tempfilepager" ascii nocase
		$tag = {3c 6f 66 66 69 63 65 3a 64 6f 63 }

	condition:
		uint32be(0)==0x3c3f786d and $tag in (0..0100) and all of ($s*)
}
