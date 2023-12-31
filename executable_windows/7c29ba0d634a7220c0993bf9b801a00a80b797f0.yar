rule Jupyter_Infostealer_DLL
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "observed wide strings with malicious DLL loaded by Jupyer malware"
		reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html"
		os = "windows"
		filetype = "executable"

	strings:
		$reggie = /[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\.dll/ wide
		$web = /https?:/ nocase wide
		$negate1 = "saitek" nocase wide

	condition:
		($reggie and $web) and not $negate1
}
