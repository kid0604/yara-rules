rule Suspicious_PS_Strings
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "observed set of strings which are likely malicious, observed with Jupyter malware. "
		reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html"
		os = "windows"
		filetype = "script"

	strings:
		$a = "windowstyle=7" nocase
		$b = "[system.io.file]:" nocase
		$c = ":readallbytes" nocase
		$d = "system.text.encoding]::" nocase
		$e = "utf8.getstring" nocase
		$f = "([system.convert]::" nocase
		$g = "frombase64string" nocase
		$h = "[system.reflection.assembly]::load" nocase
		$i = "-bxor" nocase

	condition:
		6 of them
}
