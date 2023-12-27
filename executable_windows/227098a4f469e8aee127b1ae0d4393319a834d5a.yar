rule HydraSeven_loader
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "New custom loader observed since September 2023"
		reference = "https://security5magics.blogspot.com/2023/10/interesting-customloader-observed-in.html"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$astring1 = "app.dll" ascii
		$wstring1 = "webView2" wide
		$wstring2 = /https?:\/\/.{1,35}\/main/ wide
		$d = "EmbeddedBrowserWebView.dll" wide

	condition:
		(($astring1 and $wstring1 and $wstring2) or ($d and $wstring2)) and $mz at 0 and filesize <1MB
}
