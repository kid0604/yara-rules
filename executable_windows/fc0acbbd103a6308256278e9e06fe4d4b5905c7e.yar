rule bin_wuaus
{
	meta:
		description = "Webshells Auto-generated - file wuaus.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "46a365992bec7377b48a2263c49e4e7d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "9(90989@9V9^9f9n9v9"
		$s2 = ":(:,:0:4:8:C:H:N:T:Y:_:e:o:y:"
		$s3 = ";(=@=G=O=T=X=\\="
		$s4 = "TCP Send Error!!"
		$s5 = "1\"1;1X1^1e1m1w1~1"
		$s8 = "=$=)=/=<=Y=_=j=p=z="

	condition:
		all of them
}
