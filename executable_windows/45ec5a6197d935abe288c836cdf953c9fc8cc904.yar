import "pe"

rule zoxPNG_RAT
{
	meta:
		Author = "Novetta Advanced Research Group"
		Date = "2014/11/14"
		Description = "ZoxPNG RAT, url inside"
		Reference = "http://www.novetta.com/wp-content/uploads/2014/11/ZoxPNG.pdf"
		description = "Detects ZoxPNG RAT with URL inside"
		os = "windows"
		filetype = "executable"

	strings:
		$url = "png&w=800&h=600&ei=CnJcUcSBL4rFkQX444HYCw&zoom=1&ved=1t:3588,r:1,s:0,i:92&iact=rc&dur=368&page=1&tbnh=184&tbnw=259&start=0&ndsp=20&tx=114&ty=58"

	condition:
		$url
}
