rule Jupyter_Dropped_File
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "observed wide strings with malicious DLL loaded by Jupyer malware"
		reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "solarmarker.dat" nocase wide

	condition:
		all of them
}
