rule WEBSHELL_ProxyShell_Exploitation_Nov21_1
{
	meta:
		description = "Detects webshells dropped by DropHell malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.deepinstinct.com/blog/do-not-exchange-it-has-a-shell-inside"
		date = "2021-11-01"
		score = 85
		os = "windows,linux"
		filetype = "script"

	strings:
		$s01 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Request[" ascii wide
		$s02 = "new System.IO.MemoryStream()" ascii wide
		$s03 = "Transform(" ascii wide

	condition:
		all of ($s*)
}
