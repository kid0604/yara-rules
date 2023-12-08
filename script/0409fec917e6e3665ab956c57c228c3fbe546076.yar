rule EXPL_POC_SpringCore_0day_Indicators_Mar22_1
{
	meta:
		description = "Detects indicators found after SpringCore exploitation attempts and in the POC script"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/vxunderground/status/1509170582469943303"
		date = "2022-03-30"
		score = 70
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di"
		$x2 = "?pwd=j&cmd=whoami"
		$x3 = ".getParameter(%22pwd%22)"
		$x4 = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7B"

	condition:
		1 of them
}
